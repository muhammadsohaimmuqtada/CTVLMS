#!/usr/bin/env php
<?php
/**
 * One continuous exposure-management cycle with overlap protection and bounded
 * child execution.
 *
 * Optional environment:
 *   CTVLMS_SCAN_TARGETS=192.168.1.0/24,10.0.0.10
 *   CTVLMS_LOCAL_ASSET_IDS=1,7
 *   CTVLMS_SSH_INVENTORY_ASSET_IDS=2,3
 *   CTVLMS_PACKAGE_ADVISORY_SYNC_HOURS=24   # 0 disables scheduled feed sync
 *   CTVLMS_EXECUTE_PATCHES=0
 *   CTVLMS_MAX_PATCHES_PER_CYCLE=5
 */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/sync_cve.php';
require_once __DIR__ . '/../includes/exposure.php';
require_once __DIR__ . '/../includes/package_engine_v2.php';
require_once __DIR__ . '/../includes/process.php';
require_once __DIR__ . '/../includes/scheduler.php';

function runCycleChild(array $command, int $timeoutSeconds, int $maxOutputBytes = 16777216): array
{
    $result = runBoundedProcess($command, $timeoutSeconds, $maxOutputBytes);
    return [
        'exit'=>$result['exit'],
        'stdout'=>trim((string)$result['stdout']),
        'stderr'=>trim((string)$result['stderr']),
        'timed_out'=>$result['timed_out'],
        'output_exceeded'=>$result['output_exceeded'],
        'duration_seconds'=>$result['duration_seconds'],
    ];
}

function configuredAssetIDs(string $envName): array
{
    $ids = array_values(array_filter(array_map('trim', explode(',', (string)getenv($envName)))));
    $out = [];
    foreach ($ids as $id) {
        if (!ctype_digit($id) || (int)$id < 1) $out[] = ['raw'=>$id,'valid'=>false];
        else $out[] = ['raw'=>$id,'valid'=>true,'id'=>(int)$id];
    }
    return $out;
}

function childStage(array $result, array $metadata = []): array
{
    $error = $result['exit'] === 0 ? null : ($result['stderr'] !== '' ? $result['stderr'] : $result['stdout']);
    return $metadata + [
        'ok'=>$result['exit'] === 0,
        'exit'=>$result['exit'],
        'duration_seconds'=>$result['duration_seconds'],
        'timed_out'=>$result['timed_out'],
        'output_exceeded'=>$result['output_exceeded'],
        'output'=>$result['exit'] === 0 ? $result['stdout'] : $error,
    ];
}

$db = getDB();
$workerID = schedulerWorkerID();
$cycleRunID = null;
$lockHeld = false;
$summary = [
    'worker_id'=>$workerID,
    'started_at'=>gmdate(DATE_ATOM),
    'package_advisory_sync'=>null,
    'nvd'=>['ok'=>false,'processed'=>0],
    'local_inventory'=>[],
    'ssh_inventory'=>[],
    'scans'=>[],
    'correlation'=>null,
    'package_correlation'=>null,
    'jobs_queued'=>0,
    'patches'=>[],
    'verification'=>null,
    'fatal_error'=>null,
];

try {
    $lockHeld = tryAcquireCycleLock($db);
    if (!$lockHeld) {
        $summary['skipped']='another continuous cycle already owns the scheduler lock';
        $summary['finished_at']=gmdate(DATE_ATOM);
        $cycleRunID=createCycleRun(
            $db,$workerID,'Skipped',
            json_encode($summary,JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            'Cycle overlap prevented by MariaDB named lock.'
        );
        $summary['cycle_run_id']=$cycleRunID;
        echo json_encode($summary,JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES).PHP_EOL;
        exit(0);
    }

    $cycleRunID=createCycleRun($db,$workerID);
    $summary['cycle_run_id']=$cycleRunID;

    $cadence=packageAdvisorySyncCadenceHours();
    $syncDue=packageAdvisorySyncDue($db,$cadence);
    if ($syncDue['due']) {
        $timeout=boundedTimeoutFromEnv('CTVLMS_PACKAGE_ADVISORY_TIMEOUT_SECONDS',900,60,3600);
        $result=runCycleChild([PHP_BINARY,__DIR__.'/sync-package-advisories.php'],$timeout,8388608);
        $summary['package_advisory_sync']=childStage($result,[
            'due'=>true,
            'reason'=>$syncDue['reason'],
            'last_success'=>$syncDue['last_success'],
            'cadence_hours'=>$cadence,
        ]);
    } else {
        $summary['package_advisory_sync']=[
            'ok'=>true,'due'=>false,'skipped'=>true,
            'reason'=>$syncDue['reason'],'last_success'=>$syncDue['last_success'],
            'cadence_hours'=>$cadence,
        ];
    }

    try {
        $nvd=syncNistCVEs($db);
        $summary['nvd']=['ok'=>$nvd!==false,'processed'=>$nvd===false?0:$nvd];
        if ($nvd===false) $summary['nvd']['error']='NVD synchronization returned failure.';
    } catch (Throwable $error) {
        $summary['nvd']=['ok'=>false,'processed'=>0,'error'=>$error->getMessage()];
    }

    $localTimeout=boundedTimeoutFromEnv('CTVLMS_LOCAL_INVENTORY_TIMEOUT_SECONDS',300,30,1800);
    foreach (configuredAssetIDs('CTVLMS_LOCAL_ASSET_IDS') as $entry) {
        if (!$entry['valid']) {
            $summary['local_inventory'][]=['asset_id'=>$entry['raw'],'ok'=>false,'output'=>'Invalid asset ID'];
            continue;
        }
        $result=runCycleChild([PHP_BINARY,__DIR__.'/inventory-local.php',(string)$entry['id']],$localTimeout,8388608);
        $summary['local_inventory'][]=childStage($result,['asset_id'=>$entry['id']]);
    }

    $sshTimeout=boundedTimeoutFromEnv('CTVLMS_SSH_INVENTORY_TIMEOUT_SECONDS',600,60,1800);
    foreach (configuredAssetIDs('CTVLMS_SSH_INVENTORY_ASSET_IDS') as $entry) {
        if (!$entry['valid']) {
            $summary['ssh_inventory'][]=['asset_id'=>$entry['raw'],'ok'=>false,'output'=>'Invalid asset ID'];
            continue;
        }
        $result=runCycleChild([PHP_BINARY,__DIR__.'/inventory-ssh.php',(string)$entry['id']],$sshTimeout,8388608);
        $summary['ssh_inventory'][]=childStage($result,['asset_id'=>$entry['id']]);
    }

    $scanTimeout=boundedTimeoutFromEnv('CTVLMS_SCAN_TIMEOUT_SECONDS',900,30,1800);
    $targets=array_values(array_filter(array_map('trim',explode(',',(string)getenv('CTVLMS_SCAN_TARGETS')))));
    foreach ($targets as $target) {
        $result=runCycleChild([PHP_BINARY,__DIR__.'/scan-network.php',$target],$scanTimeout,16777216);
        $summary['scans'][]=childStage($result,['target'=>$target]);
    }

    $summary['correlation']=evaluateExposureInventory($db);
    $summary['package_correlation']=evaluatePackageAdvisoriesV2($db);
    $summary['jobs_queued']=queueEligibleRemediationJobs($db);

    if (getenv('CTVLMS_EXECUTE_PATCHES')==='1') {
        $limit=max(1,min(50,(int)(getenv('CTVLMS_MAX_PATCHES_PER_CYCLE') ?: 5)));
        $patchTimeout=boundedTimeoutFromEnv('CTVLMS_PATCH_WORKER_TIMEOUT_SECONDS',3600,120,3600);
        for ($i=0;$i<$limit;$i++) {
            $result=runCycleChild([PHP_BINARY,__DIR__.'/patch-worker.php'],$patchTimeout,16777216);
            if ($result['exit']===0 && str_contains($result['stdout'],'No executable remediation jobs')) break;
            $summary['patches'][]=childStage($result,['sequence'=>$i+1]);
            if ($result['exit']!==0) break;
        }
    }

    $verifyTimeout=boundedTimeoutFromEnv('CTVLMS_VERIFICATION_TIMEOUT_SECONDS',600,30,1800);
    $verification=runCycleChild([PHP_BINARY,__DIR__.'/verify-remediations.php'],$verifyTimeout,16777216);
    $summary['verification']=childStage($verification);
    $summary['finished_at']=gmdate(DATE_ATOM);

    $status=deriveCycleStatus($summary);
    finishCycleRun($db,$cycleRunID,$status,$summary);
    logAction('CYCLE','continuous_cycle_runs',$cycleRunID,"Continuous exposure-management cycle completed with status {$status}");
    echo json_encode($summary,JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES).PHP_EOL;
    exit($status==='Failed' ? 1 : 0);
} catch (Throwable $error) {
    $summary['fatal_error']=$error->getMessage();
    $summary['finished_at']=gmdate(DATE_ATOM);
    if ($cycleRunID !== null) {
        try { finishCycleRun($db,$cycleRunID,'Failed',$summary,$error->getMessage()); } catch (Throwable) {}
    }
    try { logAction('CYCLE_FAILED','continuous_cycle_runs',$cycleRunID,'Continuous cycle failed: '.$error->getMessage()); } catch (Throwable) {}
    fwrite(STDERR,'Continuous cycle failed: '.$error->getMessage().PHP_EOL);
    echo json_encode($summary,JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES).PHP_EOL;
    exit(1);
} finally {
    if ($lockHeld) releaseCycleLock($db);
}
