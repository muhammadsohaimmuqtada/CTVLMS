#!/usr/bin/env php
<?php
/**
 * Hardened continuous cycle using scalable package intelligence.
 * Existing bin/continuous-cycle.php remains available for compatibility while
 * rollout validation is performed.
 */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/sync_cve.php';
require_once __DIR__ . '/../includes/exposure.php';
require_once __DIR__ . '/../includes/package_evaluator.php';

function runChildV2(array $command): array
{
    $descriptor = [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
    $proc = proc_open($command, $descriptor, $pipes);
    if (!is_resource($proc)) throw new RuntimeException('Unable to launch child process.');
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    $exit = proc_close($proc);
    return ['exit'=>$exit,'stdout'=>trim($stdout),'stderr'=>trim($stderr)];
}

$db = getDB();
$summary = [
    'started_at'=>gmdate(DATE_ATOM),
    'nvd'=>['ok'=>false,'processed'=>0],
    'local_inventory'=>[],
    'scans'=>[],
    'correlation'=>null,
    'package_correlation'=>null,
    'jobs_queued'=>0,
    'patches'=>[],
    'verification'=>null,
];

try {
    $nvd = syncNistCVEs($db);
    $summary['nvd'] = ['ok'=>$nvd !== false, 'processed'=>$nvd === false ? 0 : $nvd];
} catch (Throwable $e) {
    $summary['nvd'] = ['ok'=>false,'processed'=>0,'error'=>$e->getMessage()];
}

$localIDs = array_values(array_filter(array_map('trim', explode(',', (string)getenv('CTVLMS_LOCAL_ASSET_IDS')))));
foreach ($localIDs as $assetID) {
    if (!ctype_digit($assetID) || (int)$assetID < 1) {
        $summary['local_inventory'][] = ['asset_id'=>$assetID,'ok'=>false,'output'=>'Invalid asset ID'];
        continue;
    }
    $result = runChildV2([PHP_BINARY, __DIR__ . '/inventory-local.php', $assetID]);
    $summary['local_inventory'][] = ['asset_id'=>(int)$assetID,'ok'=>$result['exit']===0,'output'=>$result['exit']===0?$result['stdout']:$result['stderr']];
}

$targets = array_values(array_filter(array_map('trim', explode(',', (string)getenv('CTVLMS_SCAN_TARGETS')))));
foreach ($targets as $target) {
    $result = runChildV2([PHP_BINARY, __DIR__ . '/scan-network.php', $target]);
    $summary['scans'][] = ['target'=>$target,'ok'=>$result['exit']===0,'output'=>$result['exit']===0?$result['stdout']:$result['stderr']];
}

$summary['correlation'] = evaluateExposureInventory($db);
$summary['package_correlation'] = evaluatePackageAdvisoriesScalable($db);
$summary['jobs_queued'] = queueEligibleRemediationJobs($db);

if (getenv('CTVLMS_EXECUTE_PATCHES') === '1') {
    $limit = max(1, min(50, (int)(getenv('CTVLMS_MAX_PATCHES_PER_CYCLE') ?: 5)));
    for ($i=0; $i<$limit; $i++) {
        $result = runChildV2([PHP_BINARY, __DIR__ . '/patch-worker.php']);
        if (str_contains($result['stdout'], 'No executable remediation jobs.')) break;
        $summary['patches'][] = ['ok'=>$result['exit']===0,'output'=>$result['exit']===0?$result['stdout']:$result['stderr']];
        if ($result['exit'] !== 0) break;
    }
}

$verification = runChildV2([PHP_BINARY, __DIR__ . '/verify-remediations.php']);
$summary['verification'] = ['ok'=>$verification['exit']===0,'output'=>$verification['exit']===0?$verification['stdout']:$verification['stderr']];
$summary['finished_at'] = gmdate(DATE_ATOM);
logAction('CYCLE','exposure_matches',null,'Hardened continuous exposure-management cycle completed');
echo json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
