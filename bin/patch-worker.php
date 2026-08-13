#!/usr/bin/env php
<?php
/** Policy-gated, leased package remediation worker. Executes at most one job. */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/remediation.php';
require_once __DIR__ . '/../includes/remediation_queue.php';
require_once __DIR__ . '/../includes/remediation_rollout.php';
require_once __DIR__ . '/../includes/ssh_transport.php';

function runPatchSsh(PDO $db, array $job, string $remoteCommand, int $timeoutSeconds): array
{
    $keyPath=requiredFileFromEnv((string)$job['sshKeyEnv'],'SSH private key');
    $knownHostsPath=requiredFileFromEnv((string)$job['sshKnownHostsEnv'],'SSH known-hosts');
    $argv=buildStrictSshArgv(
        (string)$job['ipAddress'],(string)$job['sshUser'],$keyPath,$knownHostsPath,$remoteCommand,10
    );
    $heartbeat=function() use ($db,$job): void {
        heartbeatRemediationLease($db,(int)$job['jobID'],(string)$job['leaseToken']);
    };
    return runBoundedProcess($argv,$timeoutSeconds,16777216,$heartbeat,15);
}

function firstOutputLine(array $result): string
{
    $lines=preg_split('/\R/',trim((string)$result['stdout'])) ?: [];
    return trim((string)($lines[0] ?? ''));
}

function recordRolloutOutcomeSafe(PDO $db, array $job, bool $success, string $details): void
{
    try {
        $outcome=recordRemediationRolloutOutcome($db,$job,$success,$details);
        if (!empty($outcome['auto_paused'])) {
            logAction(
                'ROLLOUT_AUTO_PAUSED','remediation_rollout_groups',(int)$outcome['group_id'],
                'Rollout group auto-paused after remediation failure on job #'.(int)$job['jobID']
            );
        }
    } catch (Throwable $error) {
        // Rollout telemetry must never rewrite the already-determined patch
        // outcome. Surface it separately for operators.
        logAction(
            'ROLLOUT_EVENT_FAILED','remediation_jobs',(int)$job['jobID'],
            'Unable to record rollout outcome: '.$error->getMessage()
        );
    }
}

$db=getDB();
try {
    $job=claimRemediationJob($db);
} catch (Throwable $error) {
    fwrite(STDERR,'Unable to claim remediation job: '.$error->getMessage().PHP_EOL);
    exit(1);
}
if ($job===null) {
    echo "No executable remediation jobs in the current policy/maintenance window.\n";
    exit(0);
}

try {
    $rolloutDecision=remediationRolloutDecision($db,$job);
    if (!$rolloutDecision['allowed']) {
        deferClaimForRemediationRollout($db,$job,$rolloutDecision);
        $group=$rolloutDecision['group'] ?? null;
        logAction(
            'PATCH_ROLLOUT_DEFERRED','remediation_jobs',(int)$job['jobID'],
            'Deferred by rollout policy: '.$rolloutDecision['reason'].
            ($group ? '; group='.(string)$group['groupName'] : '')
        );
        echo "Patch job #{$job['jobID']} deferred by remediation rollout policy: {$rolloutDecision['reason']}.\n";
        exit(0);
    }
} catch (Throwable $error) {
    // A rollout-control failure is a policy failure: never fall through and
    // execute the patch when blast-radius policy cannot be evaluated.
    try {
        failOrRetryRemediationJob($db,$job,'Unable to evaluate remediation rollout policy: '.$error->getMessage(),'rollout_policy_error',false);
    } catch (Throwable) {}
    fwrite(STDERR,'Remediation rollout policy evaluation failed: '.$error->getMessage().PHP_EOL);
    exit(1);
}

logAction('PATCH_CLAIMED','remediation_jobs',(int)$job['jobID'],
    'Worker '.$job['workerID'].' claimed attempt '.$job['attemptCount'] .
    (!empty($job['reclaimedExpiredLease']) ? ' after expired lease' : ''));
logAction('STATUS_CHANGE','asset_vulnerabilities',(int)$job['assetVulnID'],'Automated remediation attempt started');

try {
    [$versionCommand,$upgradeCommand]=packageCommands((string)$job['packageManager'],(string)$job['packageName']);
    heartbeatRemediationLease($db,(int)$job['jobID'],(string)$job['leaseToken']);

    $before=runPatchSsh($db,$job,$versionCommand,60);
    if ($before['exit']!==0 || firstOutputLine($before)==='') {
        $message='Unable to determine installed package version before upgrade: '.
            (trim((string)$before['stderr']) ?: 'transport/probe failure');
        $retryable=($before['exit']===255 || !empty($before['timed_out']));
        $result=failOrRetryRemediationJob($db,$job,$message,'preflight_transport',$retryable);
        logAction('PATCH_RETRY','remediation_jobs',(int)$job['jobID'],$message);
        fwrite(STDERR,"Patch job #{$job['jobID']} preflight failed" . (!empty($result['retry_scheduled']) ? '; retry scheduled.' : '.') . "\n");
        exit(1);
    }
    $beforeVersion=firstOutputLine($before);

    // A reclaimed/queued job must still refer to the exact version that was
    // evaluated when the job was created. If inventory changed, do not patch on
    // stale applicability; require a fresh inventory/correlation cycle instead.
    $expected=trim((string)($job['fromVersion'] ?: $job['inventoryVersion']));
    if ($expected!=='' && $beforeVersion!==$expected) {
        $message="Installed version {$beforeVersion} differs from evaluated job version {$expected}; fresh applicability evaluation required.";
        failOrRetryRemediationJob($db,$job,$message,'inventory_changed',false);
        logAction('PATCH_ABORTED_STALE','remediation_jobs',(int)$job['jobID'],$message);
        fwrite(STDERR,"Patch job #{$job['jobID']} aborted: {$message}\n");
        exit(1);
    }

    heartbeatRemediationLease($db,(int)$job['jobID'],(string)$job['leaseToken']);
    $upgrade=runPatchSsh($db,$job,$upgradeCommand,max(60,(int)$job['patchCommandTimeoutSeconds']));
    if ($upgrade['exit']!==0) {
        $unknown=($upgrade['exit']===255 || !empty($upgrade['timed_out']));
        $failureClass=$unknown?'execution_outcome_unknown':'upgrade_failed';
        $message='Package upgrade failed'.($unknown?' with unknown remote execution outcome':'').': '.
            (trim((string)$upgrade['stderr']) ?: trim((string)$upgrade['stdout']) ?: 'unknown error');
        failOrRetryRemediationJob($db,$job,$message,$failureClass,false);
        recordRolloutOutcomeSafe($db,$job,false,$failureClass.': '.$message);
        logAction('PATCH_FAILED','remediation_jobs',(int)$job['jobID'],$message);
        fwrite(STDERR,"Patch job #{$job['jobID']} failed: {$message}\n");
        exit(1);
    }

    heartbeatRemediationLease($db,(int)$job['jobID'],(string)$job['leaseToken']);
    $after=runPatchSsh($db,$job,$versionCommand,60);
    if ($after['exit']!==0 || firstOutputLine($after)==='') {
        $message='Upgrade command returned success but post-upgrade version could not be verified; fresh inventory required.';
        failOrRetryRemediationJob($db,$job,$message,'execution_outcome_unknown',false);
        recordRolloutOutcomeSafe($db,$job,false,'execution_outcome_unknown: '.$message);
        logAction('PATCH_VERIFY_TRANSPORT_FAILED','remediation_jobs',(int)$job['jobID'],$message);
        fwrite(STDERR,"Patch job #{$job['jobID']} requires re-evaluation: {$message}\n");
        exit(1);
    }
    $afterVersion=firstOutputLine($after);
    if ($beforeVersion===$afterVersion) {
        $message='Upgrade command completed but installed package version did not change.';
        failOrRetryRemediationJob($db,$job,$message,'no_version_change',false);
        recordRolloutOutcomeSafe($db,$job,false,'no_version_change: '.$message);
        logAction('PATCH_FAILED','remediation_jobs',(int)$job['jobID'],$message);
        fwrite(STDERR,"Patch job #{$job['jobID']} failed: {$message}\n");
        exit(1);
    }

    $evidence=json_encode([
        'package'=>$job['packageName'],'package_manager'=>$job['packageManager'],
        'before_version'=>$beforeVersion,'after_version'=>$afterVersion,'transport'=>'SSH',
        'worker_id'=>$job['workerID'],'attempt'=>(int)$job['attemptCount'],
        'completed_at'=>gmdate(DATE_ATOM),
        'verification_requirement'=>'fresh_managed_inventory_after_job_completion',
    ],JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

    $db->beginTransaction();
    try {
        $remediation=$db->prepare(
            "INSERT INTO remediations (assetVulnID,actionTaken,remediationType,startedDate,completedDate)
             VALUES (:assetVuln,:action,'Patch',CURDATE(),CURDATE())"
        );
        $remediation->execute([
            ':assetVuln'=>$job['assetVulnID'],
            ':action'=>"CTVLMS package upgrade: {$job['packageName']} {$beforeVersion} → {$afterVersion}",
        ]);
        $remediationID=(int)$db->lastInsertId();
        fencedJobUpdate(
            $db,(int)$job['jobID'],(string)$job['leaseToken'],
            "status='Succeeded',remediationID=:remediation,fromVersion=:before,targetVersion=:after,
             completedAt=CURRENT_TIMESTAMP,verificationEvidence=:evidence,
             leaseToken=NULL,workerID=NULL,leasedUntil=NULL,lastHeartbeatAt=NULL,lastFailureClass=NULL",
            [':remediation'=>$remediationID,':before'=>$beforeVersion,':after'=>$afterVersion,':evidence'=>$evidence]
        );
        // Do not mutate asset_software/package inventory here. A single command
        // probe is execution evidence, not a complete authoritative inventory snapshot.
        $db->prepare("UPDATE exposure_matches SET status='Remediated' WHERE exposureID=:id")
            ->execute([':id'=>$job['exposureID']]);
        $db->prepare("UPDATE asset_vulnerabilities SET status='Remediated' WHERE assetVulnID=:id AND status='Remediation_In_Progress'")
            ->execute([':id'=>$job['assetVulnID']]);
        logAction('CREATE','remediations',$remediationID,'Created from leased patch job #'.$job['jobID']);
        logAction('AUTO_PATCH','remediation_jobs',(int)$job['jobID'],"Upgraded {$job['packageName']} {$beforeVersion} → {$afterVersion}");
        logAction('STATUS_CHANGE','asset_vulnerabilities',(int)$job['assetVulnID'],'Status: Remediation_In_Progress → Remediated; fresh inventory required for closure');
        $db->commit();
    } catch (Throwable $error) {
        if ($db->inTransaction()) $db->rollBack();
        throw $error;
    }
    recordRolloutOutcomeSafe($db,$job,true,"Succeeded: {$job['packageName']} {$beforeVersion} -> {$afterVersion}");
    echo "Patched job #{$job['jobID']}: {$job['packageName']} {$beforeVersion} -> {$afterVersion}; awaiting fresh managed inventory.\n";
} catch (Throwable $error) {
    if ($db->inTransaction()) $db->rollBack();
    // If the failure occurred outside one of the explicitly handled paths, fence
    // the state transition. Policy/credential errors are not blindly retried.
    try {
        failOrRetryRemediationJob($db,$job,$error->getMessage(),'worker_error',false);
        recordRolloutOutcomeSafe($db,$job,false,'worker_error: '.$error->getMessage());
    } catch (Throwable $leaseError) {
        fwrite(STDERR,'Worker lost remediation lease while handling failure: '.$leaseError->getMessage().PHP_EOL);
        exit(1);
    }
    logAction('PATCH_FAILED','remediation_jobs',(int)$job['jobID'],$error->getMessage());
    fwrite(STDERR,"Patch job #{$job['jobID']} failed: {$error->getMessage()}\n");
    exit(1);
}
