<?php
/** Staged/canary remediation rollout policy and blast-radius controls. */

function remediationRolloutBucket(int $groupID, int $assetID): int
{
    $digest = hash('sha256', $groupID . ':' . $assetID);
    return (int)(hexdec(substr($digest, 0, 8)) % 100);
}

function remediationRolloutState(PDO $db, int $assetID): ?array
{
    $stmt = $db->prepare(
        "SELECT g.groupID,g.groupName,g.phase,g.canaryPercent,g.maxConcurrent,
                g.autoPauseOnFailure,g.failureThreshold,g.pausedReason,g.updatedAt
         FROM asset_remediation_rollouts ar
         JOIN remediation_rollout_groups g ON g.groupID=ar.groupID
         WHERE ar.assetID=:asset LIMIT 1"
    );
    $stmt->execute([':asset'=>$assetID]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function remediationRolloutDecision(PDO $db, array $job): array
{
    $assetID = (int)($job['assetID'] ?? 0);
    if ($assetID < 1) {
        return ['allowed'=>false,'reason'=>'invalid_asset','group'=>null,'bucket'=>null];
    }
    $group = remediationRolloutState($db, $assetID);
    if ($group === null) {
        return ['allowed'=>true,'reason'=>'no_rollout_group','group'=>null,'bucket'=>null];
    }

    $phase = (string)$group['phase'];
    $bucket = remediationRolloutBucket((int)$group['groupID'], $assetID);
    if ($phase === 'Paused') {
        return ['allowed'=>false,'reason'=>'rollout_group_paused','group'=>$group,'bucket'=>$bucket];
    }
    if ($phase === 'Canary' && $bucket >= (int)$group['canaryPercent']) {
        return ['allowed'=>false,'reason'=>'asset_outside_canary_bucket','group'=>$group,'bucket'=>$bucket];
    }

    $running = $db->prepare(
        "SELECT COUNT(*)
         FROM remediation_jobs j
         JOIN asset_remediation_rollouts ar ON ar.assetID=j.assetID
         WHERE ar.groupID=:group AND j.status='Running' AND j.jobID<>:job"
    );
    $running->execute([
        ':group'=>(int)$group['groupID'],
        ':job'=>(int)($job['jobID'] ?? 0),
    ]);
    $otherRunning = (int)$running->fetchColumn();
    if ($otherRunning >= max(1, (int)$group['maxConcurrent'])) {
        return [
            'allowed'=>false,'reason'=>'rollout_concurrency_limit','group'=>$group,
            'bucket'=>$bucket,'other_running'=>$otherRunning,
        ];
    }

    return [
        'allowed'=>true,
        'reason'=>$phase === 'Canary' ? 'canary_asset_allowed' : 'general_rollout_allowed',
        'group'=>$group,'bucket'=>$bucket,'other_running'=>$otherRunning,
    ];
}

function recordRemediationRolloutEvent(
    PDO $db,
    int $groupID,
    string $eventType,
    ?int $assetID = null,
    ?int $jobID = null,
    ?string $details = null
): void {
    $allowed = ['Created','Assigned','Phase_Changed','Deferred','Succeeded','Failed','Auto_Paused'];
    if (!in_array($eventType, $allowed, true)) throw new InvalidArgumentException('Invalid rollout event type.');
    $stmt = $db->prepare(
        'INSERT INTO remediation_rollout_events (groupID,assetID,jobID,eventType,details)
         VALUES (:group,:asset,:job,:type,:details)'
    );
    $stmt->execute([
        ':group'=>$groupID, ':asset'=>$assetID, ':job'=>$jobID, ':type'=>$eventType,
        ':details'=>$details === null ? null : substr($details, 0, 1000),
    ]);
}

function deferClaimForRemediationRollout(PDO $db, array $job, array $decision, int $delaySeconds = 300): void
{
    if (!empty($decision['allowed'])) return;
    $group = $decision['group'] ?? null;
    if (!is_array($group)) throw new RuntimeException('Cannot defer rollout job without group state.');
    $delaySeconds = max(60, min(3600, $delaySeconds));
    $returnStatus = ($job['mode'] ?? '') === 'Auto' ? 'Queued' : 'Approved';

    $db->beginTransaction();
    try {
        $stmt = $db->prepare(
            "UPDATE remediation_jobs
             SET status=:status,leaseToken=NULL,workerID=NULL,leasedUntil=NULL,lastHeartbeatAt=NULL,
                 attemptCount=GREATEST(attemptCount-1,0),
                 nextAttemptAt=DATE_ADD(CURRENT_TIMESTAMP,INTERVAL {$delaySeconds} SECOND),
                 lastError=:reason,lastFailureClass='rollout_deferred'
             WHERE jobID=:job AND status='Running' AND leaseToken=:lease"
        );
        $stmt->execute([
            ':status'=>$returnStatus,
            ':reason'=>'Remediation rollout deferred: ' . (string)$decision['reason'],
            ':job'=>(int)$job['jobID'], ':lease'=>(string)$job['leaseToken'],
        ]);
        if ($stmt->rowCount() !== 1) throw new RuntimeException('Remediation lease lost while applying rollout defer.');

        $db->prepare("UPDATE exposure_matches SET status='Remediation_Queued' WHERE exposureID=:id")
            ->execute([':id'=>(int)$job['exposureID']]);
        $db->prepare(
            "UPDATE asset_vulnerabilities SET status='Confirmed'
             WHERE assetVulnID=:id AND status='Remediation_In_Progress'"
        )->execute([':id'=>(int)$job['assetVulnID']]);

        recordRemediationRolloutEvent(
            $db,(int)$group['groupID'],'Deferred',(int)$job['assetID'],(int)$job['jobID'],
            (string)$decision['reason'] . '; bucket=' . (string)($decision['bucket'] ?? 'n/a')
        );
        $db->commit();
    } catch (Throwable $error) {
        if ($db->inTransaction()) $db->rollBack();
        throw $error;
    }
}

function remediationRolloutShouldAutoPause(array $group, int $recentFailures): bool
{
    return (bool)($group['autoPauseOnFailure'] ?? false)
        && $recentFailures >= max(1, (int)($group['failureThreshold'] ?? 1));
}

function recordRemediationRolloutOutcome(PDO $db, array $job, bool $success, string $details): array
{
    $group = remediationRolloutState($db, (int)$job['assetID']);
    if ($group === null) return ['grouped'=>false,'auto_paused'=>false];

    $db->beginTransaction();
    try {
        recordRemediationRolloutEvent(
            $db,(int)$group['groupID'],$success ? 'Succeeded' : 'Failed',
            (int)$job['assetID'],(int)$job['jobID'],$details
        );
        $autoPaused = false;
        if (!$success && (string)$group['phase'] !== 'Paused') {
            $failures = $db->prepare(
                "SELECT COUNT(*) FROM remediation_rollout_events
                 WHERE groupID=:group AND eventType='Failed' AND createdAt>=:since"
            );
            $failures->execute([
                ':group'=>(int)$group['groupID'],
                ':since'=>(string)$group['updatedAt'],
            ]);
            $count = (int)$failures->fetchColumn();
            if (remediationRolloutShouldAutoPause($group, $count)) {
                $reason = 'Auto-paused after ' . $count . ' remediation failure(s) in current rollout phase.';
                $pause = $db->prepare(
                    "UPDATE remediation_rollout_groups
                     SET phase='Paused',pausedReason=:reason
                     WHERE groupID=:group AND phase<>'Paused'"
                );
                $pause->execute([':reason'=>$reason, ':group'=>(int)$group['groupID']]);
                if ($pause->rowCount() === 1) {
                    recordRemediationRolloutEvent(
                        $db,(int)$group['groupID'],'Auto_Paused',(int)$job['assetID'],(int)$job['jobID'],$reason
                    );
                    $autoPaused = true;
                }
            }
        }
        $db->commit();
        return ['grouped'=>true,'group_id'=>(int)$group['groupID'],'auto_paused'=>$autoPaused];
    } catch (Throwable $error) {
        if ($db->inTransaction()) $db->rollBack();
        throw $error;
    }
}
