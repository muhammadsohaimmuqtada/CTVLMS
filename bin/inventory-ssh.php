#!/usr/bin/env php
<?php
/** Collect authoritative Linux/dpkg inventory from one explicitly managed SSH asset. */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/inventory.php';
require_once __DIR__ . '/../includes/ssh_transport.php';

$assetID = filter_var($argv[1] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
if ($assetID === false || $assetID === null) {
    fwrite(STDERR, "Usage: php bin/inventory-ssh.php <asset-id>\n");
    exit(2);
}
$db = getDB();
$policy = $db->prepare(
    "SELECT a.assetID,a.ipAddress,p.mode,p.sshUser,p.sshKeyEnv,p.knownHostsEnv,p.connectTimeoutSeconds
     FROM assets a JOIN asset_inventory_policies p ON p.assetID=a.assetID
     WHERE a.assetID=:asset LIMIT 1"
);
$policy->execute([':asset'=>(int)$assetID]);
$managed = $policy->fetch();
if (!$managed || $managed['mode'] !== 'SSH') {
    fwrite(STDERR, "Asset does not have an enabled SSH inventory policy.\n");
    exit(1);
}

$run = $db->prepare(
    "INSERT INTO inventory_runs (assetID,transport,inventorySource,status)
     VALUES (:asset,'SSH','SSH_dpkg','Running')"
);
$run->execute([':asset'=>(int)$assetID]);
$runID = (int)$db->lastInsertId();

try {
    $results = [];
    foreach (['os_release','hostname','architecture','kernel','packages'] as $probe) {
        $result = runInventorySshProbe($managed,$probe,$probe === 'packages' ? 300 : 60);
        if ($result['exit'] !== 0) {
            $error = trim((string)$result['stderr']);
            if ($result['timed_out']) $error = 'probe timed out';
            if ($result['output_exceeded']) $error = 'probe output exceeded safety limit';
            throw new RuntimeException("SSH inventory probe {$probe} failed" . ($error !== '' ? ': ' . $error : '.'));
        }
        $results[$probe] = trim((string)$result['stdout']);
    }

    $osRelease = parseOsReleaseText($results['os_release']);
    $packages = parseDpkgInventory($results['packages']);
    if (!$packages) throw new RuntimeException('Remote dpkg inventory contained no valid package records.');
    $facts = linuxFactsFromObservations(
        $osRelease,$results['hostname'],$results['architecture'],$results['kernel'],'apt'
    );
    $stored = persistManagedInventory($db,(int)$assetID,$facts,$packages,'SSH','SSH_dpkg','SSH');

    $db->prepare(
        "UPDATE inventory_runs
         SET status='Succeeded',factsObserved=:facts,packagesObserved=:packages,completedAt=CURRENT_TIMESTAMP
         WHERE inventoryRunID=:run"
    )->execute([':facts'=>count($facts),':packages'=>count($packages),':run'=>$runID]);
    logAction('INVENTORY','assets',(int)$assetID,"SSH managed inventory run #{$runID} collected " . count($packages) . ' packages');
    $stored['inventory_run_id'] = $runID;
    $stored['transport'] = 'SSH';
    echo json_encode($stored,JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (Throwable $error) {
    $db->prepare(
        "UPDATE inventory_runs SET status='Failed',completedAt=CURRENT_TIMESTAMP,errorMessage=:error
         WHERE inventoryRunID=:run"
    )->execute([':error'=>substr($error->getMessage(),0,65535),':run'=>$runID]);
    logAction('INVENTORY_FAILED','assets',(int)$assetID,"SSH managed inventory run #{$runID} failed: " . $error->getMessage());
    fwrite(STDERR,'SSH inventory failed: ' . $error->getMessage() . PHP_EOL);
    exit(1);
}
