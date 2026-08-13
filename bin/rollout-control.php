#!/usr/bin/env php
<?php
/** Operator control for staged/canary remediation rollouts. */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/remediation_rollout.php';

function rolloutUsage(): never
{
    fwrite(STDERR, "Usage:\n");
    fwrite(STDERR, "  php bin/rollout-control.php status [group-id]\n");
    fwrite(STDERR, "  php bin/rollout-control.php create <name> [canary-percent] [max-concurrent]\n");
    fwrite(STDERR, "  php bin/rollout-control.php assign <group-id> <asset-id>\n");
    fwrite(STDERR, "  php bin/rollout-control.php phase <group-id> <Canary|General|Paused> <reason>\n");
    exit(2);
}

$db = getDB();
$command = strtolower((string)($argv[1] ?? ''));
if ($command === '') rolloutUsage();

try {
    if ($command === 'status') {
        $groupID = isset($argv[2]) ? filter_var($argv[2], FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) : null;
        if (isset($argv[2]) && $groupID === false) rolloutUsage();
        $sql = "SELECT g.groupID,g.groupName,g.phase,g.canaryPercent,g.maxConcurrent,g.autoPauseOnFailure,
                       g.failureThreshold,g.pausedReason,g.updatedAt,
                       COUNT(DISTINCT ar.assetID) AS assets,
                       SUM(CASE WHEN j.status='Running' THEN 1 ELSE 0 END) AS runningJobs
                FROM remediation_rollout_groups g
                LEFT JOIN asset_remediation_rollouts ar ON ar.groupID=g.groupID
                LEFT JOIN remediation_jobs j ON j.assetID=ar.assetID";
        $params = [];
        if ($groupID !== null) { $sql .= ' WHERE g.groupID=:group'; $params[':group']=(int)$groupID; }
        $sql .= ' GROUP BY g.groupID ORDER BY g.groupID';
        $stmt = $db->prepare($sql); $stmt->execute($params);
        echo json_encode($stmt->fetchAll(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
        exit(0);
    }

    if ($command === 'create') {
        $name = trim((string)($argv[2] ?? ''));
        $canary = isset($argv[3]) ? (int)$argv[3] : 10;
        $concurrent = isset($argv[4]) ? (int)$argv[4] : 1;
        if ($name === '' || strlen($name) > 120 || $canary < 1 || $canary > 100 || $concurrent < 1 || $concurrent > 100) rolloutUsage();
        $stmt = $db->prepare(
            'INSERT INTO remediation_rollout_groups (groupName,canaryPercent,maxConcurrent) VALUES (:name,:canary,:concurrent)'
        );
        $stmt->execute([':name'=>$name,':canary'=>$canary,':concurrent'=>$concurrent]);
        $groupID = (int)$db->lastInsertId();
        recordRemediationRolloutEvent($db,$groupID,'Created',null,null,'Created via rollout-control CLI.');
        echo json_encode(['group_id'=>$groupID,'name'=>$name,'phase'=>'Canary','canary_percent'=>$canary,'max_concurrent'=>$concurrent], JSON_PRETTY_PRINT) . PHP_EOL;
        exit(0);
    }

    if ($command === 'assign') {
        $groupID = filter_var($argv[2] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
        $assetID = filter_var($argv[3] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
        if ($groupID === false || $assetID === false) rolloutUsage();
        $stmt = $db->prepare(
            'INSERT INTO asset_remediation_rollouts (assetID,groupID) VALUES (:asset,:group)
             ON DUPLICATE KEY UPDATE groupID=VALUES(groupID),assignedAt=CURRENT_TIMESTAMP'
        );
        $stmt->execute([':asset'=>(int)$assetID,':group'=>(int)$groupID]);
        recordRemediationRolloutEvent($db,(int)$groupID,'Assigned',(int)$assetID,null,'Asset assigned to rollout group.');
        echo json_encode(['group_id'=>(int)$groupID,'asset_id'=>(int)$assetID,'assigned'=>true], JSON_PRETTY_PRINT) . PHP_EOL;
        exit(0);
    }

    if ($command === 'phase') {
        $groupID = filter_var($argv[2] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
        $phaseInput = strtolower(trim((string)($argv[3] ?? '')));
        $phase = match ($phaseInput) {
            'canary' => 'Canary', 'general' => 'General', 'paused' => 'Paused', default => null,
        };
        $reason = trim(implode(' ', array_slice($argv,4)));
        if ($groupID === false || $phase === null || $reason === '') rolloutUsage();
        $stmt = $db->prepare(
            'UPDATE remediation_rollout_groups SET phase=:phase,pausedReason=:paused WHERE groupID=:group'
        );
        $stmt->execute([
            ':phase'=>$phase, ':paused'=>$phase === 'Paused' ? substr($reason,0,500) : null, ':group'=>(int)$groupID,
        ]);
        if ($stmt->rowCount() === 0) {
            $exists=$db->prepare('SELECT 1 FROM remediation_rollout_groups WHERE groupID=:group');
            $exists->execute([':group'=>(int)$groupID]);
            if (!$exists->fetchColumn()) throw new RuntimeException('Unknown rollout group.');
        }
        recordRemediationRolloutEvent($db,(int)$groupID,'Phase_Changed',null,null,$phase . ': ' . $reason);
        echo json_encode(['group_id'=>(int)$groupID,'phase'=>$phase,'reason'=>$reason], JSON_PRETTY_PRINT) . PHP_EOL;
        exit(0);
    }

    rolloutUsage();
} catch (Throwable $error) {
    fwrite(STDERR, 'Rollout control failed: ' . $error->getMessage() . PHP_EOL);
    exit(1);
}
