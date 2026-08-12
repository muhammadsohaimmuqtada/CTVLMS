#!/usr/bin/env php
<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/inventory.php';

$assetID = filter_var($argv[1] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
if ($assetID === false || $assetID === null) {
    fwrite(STDERR,"Usage: php bin/inventory-local.php <asset-id>\n");
    exit(2);
}
$db=getDB();
$run=$db->prepare(
    "INSERT INTO inventory_runs (assetID,transport,inventorySource,status)
     VALUES (:asset,'Local','Local_dpkg','Running')"
);
$run->execute([':asset'=>(int)$assetID]);
$runID=(int)$db->lastInsertId();
try {
    $result=collectLocalInventory($db,(int)$assetID);
    $db->prepare(
        "UPDATE inventory_runs
         SET status='Succeeded',factsObserved=:facts,packagesObserved=:packages,completedAt=CURRENT_TIMESTAMP
         WHERE inventoryRunID=:run"
    )->execute([':facts'=>count($result['facts']),':packages'=>$result['packages'],':run'=>$runID]);
    logAction('INVENTORY','assets',(int)$assetID,"Authoritative local inventory run #{$runID} completed");
    $result['inventory_run_id']=$runID;
    $result['transport']='Local';
    echo json_encode($result,JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES).PHP_EOL;
} catch (Throwable $e) {
    $db->prepare(
        "UPDATE inventory_runs SET status='Failed',completedAt=CURRENT_TIMESTAMP,errorMessage=:error WHERE inventoryRunID=:run"
    )->execute([':error'=>substr($e->getMessage(),0,65535),':run'=>$runID]);
    logAction('INVENTORY_FAILED','assets',(int)$assetID,"Local inventory run #{$runID} failed: ".$e->getMessage());
    fwrite(STDERR,"Local inventory failed: {$e->getMessage()}\n");
    exit(1);
}
