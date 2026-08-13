#!/usr/bin/env php
<?php
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../lib.php';

ctvlmsLabAssertIsolation();
$db = getDB();

$assets = [
    ['name'=>'ctvlms-lab-canary', 'ip'=>'172.28.77.11', 'mode'=>'Auto'],
    ['name'=>'ctvlms-lab-general','ip'=>'172.28.77.12', 'mode'=>'Approval'],
    ['name'=>'ctvlms-lab-stale',  'ip'=>'172.28.77.13', 'mode'=>'Auto'],
    ['name'=>'ctvlms-lab-failure','ip'=>'172.28.77.14', 'mode'=>'Auto'],
    ['name'=>'ctvlms-lab-cancel', 'ip'=>'172.28.77.15', 'mode'=>'Auto'],
];

$db->beginTransaction();
try {
    // Dedicated disposable DB only. This makes repeated lab runs deterministic.
    $db->exec("DELETE FROM vulnerabilities WHERE cveID='CVE-2099-7701'");
    $db->exec("DELETE FROM assets WHERE assetName LIKE 'ctvlms-lab-%'");
    $db->exec("DELETE FROM remediation_rollout_groups WHERE groupName LIKE 'ctvlms-lab-%'");
    $db->exec("DELETE FROM distribution_advisories WHERE provider='CTVLMSPilotLab'");

    $insertAsset = $db->prepare(
        "INSERT INTO assets (assetName,assetType,ipAddress,osPlatform,environment)
         VALUES (:name,'Server',:ip,'Debian 12','Test')"
    );
    $inventoryPolicy = $db->prepare(
        "INSERT INTO asset_inventory_policies
            (assetID,mode,sshUser,sshKeyEnv,knownHostsEnv,connectTimeoutSeconds)
         VALUES (:asset,'SSH','ctvlms-inventory','CTVLMS_LAB_SSH_KEY','CTVLMS_LAB_KNOWN_HOSTS',5)"
    );
    $patchPolicy = $db->prepare(
        "INSERT INTO asset_patch_policies
            (assetID,mode,allowMajorUpgrade,allowReboot,requireVerifiedBackup,transport,
             sshUser,sshKeyEnv,sshKnownHostsEnv,maintenanceTimezone,maintenanceDays,
             maintenanceStart,maintenanceEnd,maxPatchAttempts,patchCommandTimeoutSeconds)
         VALUES
            (:asset,:mode,0,0,1,'SSH','ctvlms-patcher','CTVLMS_LAB_SSH_KEY','CTVLMS_LAB_KNOWN_HOSTS',
             'UTC',NULL,NULL,NULL,3,120)"
    );
    $backup = $db->prepare(
        "INSERT INTO asset_backup_evidence (assetID,source,referenceValue,lastVerifiedAt,validUntil)
         VALUES (:asset,'CTVLMS Pilot Lab','disposable-container-snapshot',CURRENT_TIMESTAMP,
                 DATE_ADD(CURRENT_TIMESTAMP,INTERVAL 1 DAY))"
    );

    $ids=[];
    foreach ($assets as $asset) {
        $insertAsset->execute([':name'=>$asset['name'],':ip'=>$asset['ip']]);
        $id=(int)$db->lastInsertId();
        $ids[$asset['name']]=$id;
        $inventoryPolicy->execute([':asset'=>$id]);
        $patchPolicy->execute([':asset'=>$id,':mode'=>$asset['mode']]);
        $backup->execute([':asset'=>$id]);
    }

    $db->prepare(
        "INSERT INTO vulnerabilities (cveID,title,description,cvssScore,severity,publishedDate)
         VALUES ('CVE-2099-7701','CTVLMS pilot-lab package upgrade fixture',
                 'Synthetic lab-only advisory used to prove end-to-end remediation.',7.5,'High',CURDATE())"
    )->execute();

    $db->prepare(
        "INSERT INTO distribution_advisory_sync_runs
            (provider,dataSourceIdentifier,sourceUrl,status,recordsProcessed,recordsStored,completedAt)
         VALUES ('CTVLMSPilotLab','ctvlms-pilot-lab-v1','lab://ctvlms-pilot-lab',
                 'Succeeded',1,1,CURRENT_TIMESTAMP)"
    )->execute();
    $syncRunID=(int)$db->lastInsertId();
    $recordKey=hash('sha256','CTVLMSPilotLab|CVE-2099-7701|debian|bookworm|ctvlms-lab-pkg');
    $db->prepare(
        "INSERT INTO distribution_advisories
            (recordKey,advisoryIdentifier,cveID,distribution,suite,sourcePackage,state,fixedVersion,
             urgency,severity,upstreamReference,sourceUrl,dataSourceIdentifier,provider,lastSyncRunID,
             providerRecordJson,lastSyncedAt)
         VALUES
            (:key,'CVE-2099-7701','CVE-2099-7701','debian','bookworm','ctvlms-lab-pkg','Fixed','1.1',
             'high','High','lab://ctvlms-lab-pkg','lab://ctvlms-pilot-lab','ctvlms-pilot-lab-v1',
             'CTVLMSPilotLab',:sync,:json,CURRENT_TIMESTAMP)"
    )->execute([
        ':key'=>$recordKey, ':sync'=>$syncRunID,
        ':json'=>json_encode(['lab_fixture'=>true,'fixed_version'=>'1.1'],JSON_UNESCAPED_SLASHES),
    ]);

    $db->prepare(
        "INSERT INTO remediation_rollout_groups
            (groupName,phase,canaryPercent,maxConcurrent,autoPauseOnFailure,failureThreshold)
         VALUES ('ctvlms-lab-primary','Canary',100,1,1,1)"
    )->execute();
    $primaryGroup=(int)$db->lastInsertId();
    $db->prepare(
        "INSERT INTO remediation_rollout_groups
            (groupName,phase,canaryPercent,maxConcurrent,autoPauseOnFailure,failureThreshold)
         VALUES ('ctvlms-lab-failure','General',100,1,1,1)"
    )->execute();
    $failureGroup=(int)$db->lastInsertId();
    $assign=$db->prepare('INSERT INTO asset_remediation_rollouts (assetID,groupID) VALUES (:asset,:group)');
    $assign->execute([':asset'=>$ids['ctvlms-lab-canary'],':group'=>$primaryGroup]);
    $assign->execute([':asset'=>$ids['ctvlms-lab-general'],':group'=>$primaryGroup]);
    $assign->execute([':asset'=>$ids['ctvlms-lab-failure'],':group'=>$failureGroup]);

    $db->commit();
    echo json_encode([
        'status'=>'ready',
        'assets'=>$ids,
        'vulnerability'=>'CVE-2099-7701',
        'fixed_version'=>'1.1',
        'primary_rollout_group'=>$primaryGroup,
        'failure_rollout_group'=>$failureGroup,
    ],JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (Throwable $error) {
    if ($db->inTransaction()) $db->rollBack();
    fwrite(STDERR,'Pilot lab bootstrap failed: '.$error->getMessage().PHP_EOL);
    exit(1);
}
