<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/staging.php';

$tests = 0;
function stagingDbCheck(bool $condition, string $message): void
{
    global $tests;
    $tests++;
    if (!$condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

putenv('CTVLMS_EXECUTE_PATCHES=0');
$db = getDB();
$db->beginTransaction();
try {
    $assetIDs = [];
    foreach ([91,92] as $suffix) {
        $stmt = $db->prepare("INSERT INTO assets (assetName,assetType,ipAddress,osPlatform,criticality,environment) VALUES (:name,'Server',:ip,'Debian GNU/Linux 12','Low','Staging')");
        $stmt->execute([':name'=>"staging-fixture-{$suffix}", ':ip'=>"198.51.100.{$suffix}"]);
        $assetID = (int)$db->lastInsertId();
        $assetIDs[] = $assetID;

        $db->prepare("INSERT INTO asset_inventory_policies (assetID,mode,sshUser,sshKeyEnv,knownHostsEnv) VALUES (:asset,'SSH','ctvlms-inventory','STAGE_INV_KEY','STAGE_KNOWN_HOSTS')")
            ->execute([':asset'=>$assetID]);
        $db->prepare("INSERT INTO asset_patch_policies (assetID,mode,transport,sshUser,sshKeyEnv,sshKnownHostsEnv,allowMajorUpgrade,allowReboot,requireVerifiedBackup) VALUES (:asset,'Approval','SSH','ctvlms-patcher','STAGE_PATCH_KEY','STAGE_KNOWN_HOSTS',0,0,1)")
            ->execute([':asset'=>$assetID]);
    }

    $assessment = stagingPrepareAssessment($db, $assetIDs);
    stagingDbCheck($assessment['ok'] === true, 'safe two-node staging policy passes preflight');
    stagingDbCheck(count($assessment['assets']) === 2, 'preflight returns both selected assets');
    stagingDbCheck(count($assessment['warnings']) >= 2, 'missing initial inventory/backup is surfaced as warning, not hidden');

    $db->prepare("UPDATE asset_patch_policies SET mode='Auto' WHERE assetID=:asset")
        ->execute([':asset'=>$assetIDs[0]]);
    $assessment = stagingPrepareAssessment($db, $assetIDs);
    stagingDbCheck($assessment['ok'] === false, 'Auto policy is rejected for first real staging fleet');
    stagingDbCheck((bool)array_filter($assessment['errors'], static fn(string $e): bool => str_contains($e, 'patch mode must be Approval')), 'rejection explains Approval requirement');

    putenv('CTVLMS_EXECUTE_PATCHES=1');
    $assessment = stagingPrepareAssessment($db, $assetIDs);
    stagingDbCheck((bool)array_filter($assessment['errors'], static fn(string $e): bool => str_contains($e, 'must remain disabled')), 'preparation refuses globally enabled patch execution');

    $db->rollBack();
} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    throw $e;
} finally {
    putenv('CTVLMS_EXECUTE_PATCHES=0');
}

echo "PASS: {$tests} staging database tests\n";
