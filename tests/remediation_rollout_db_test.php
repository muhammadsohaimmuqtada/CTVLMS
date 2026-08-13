<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/remediation_queue.php';
require_once __DIR__ . '/../includes/remediation_rollout.php';

$tests=0;
function rolloutdbcheck(bool $ok,string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR,"FAIL: {$message}\n"); exit(1); }
}
$db=getDB();
$db->exec("INSERT INTO assets (assetName,assetType,ipAddress,osPlatform,environment) VALUES ('rollout-fixture','Server','198.51.100.71','Debian','Test')");
$assetID=(int)$db->lastInsertId();
$db->exec("INSERT INTO vulnerabilities (cveID,title,description,cvssScore,severity,publishedDate) VALUES ('CVE-2096-7100','Rollout fixture','fixture',7.0,'High',CURDATE())");
$vulnID=(int)$db->lastInsertId();
$db->prepare("INSERT INTO asset_vulnerabilities (assetID,vulnID,status,discoveredDate) VALUES (:asset,:vuln,'Confirmed',CURDATE())")
    ->execute([':asset'=>$assetID,':vuln'=>$vulnID]);
$assetVulnID=(int)$db->lastInsertId();
$db->prepare("INSERT INTO asset_software (assetID,product,version,cpe,packageManager,packageName,source,isActive) VALUES (:asset,'rollout-pkg','1.0','cpe:2.3:a:example:rollout-pkg:1.0:*:*:*:*:*:*:*','apt','rollout-pkg','Agent',1)")
    ->execute([':asset'=>$assetID]);
$softwareID=(int)$db->lastInsertId();
$db->prepare("INSERT INTO exposure_matches (matchKey,assetID,vulnID,softwareID,matchType,confidence,status,evidence) VALUES (:key,:asset,:vuln,:software,'CPE_Exact',0.99,'Remediation_Queued','{}')")
    ->execute([':key'=>hash('sha256','rollout-fixture'),':asset'=>$assetID,':vuln'=>$vulnID,':software'=>$softwareID]);
$exposureID=(int)$db->lastInsertId();
$db->prepare(
    "INSERT INTO asset_patch_policies
        (assetID,mode,requireVerifiedBackup,transport,sshUser,sshKeyEnv,sshKnownHostsEnv,
         maintenanceTimezone,maintenanceDays,maintenanceStart,maintenanceEnd,maxPatchAttempts,patchCommandTimeoutSeconds)
     VALUES (:asset,'Auto',0,'SSH','ctvlms-patcher','TEST_PATCH_KEY','TEST_KNOWN_HOSTS',
             'UTC',NULL,NULL,NULL,3,300)"
)->execute([':asset'=>$assetID]);
$db->prepare(
    "INSERT INTO remediation_jobs
        (exposureID,assetID,softwareID,packageManager,packageName,fromVersion,status,maxAttempts)
     VALUES (:exposure,:asset,:software,'apt','rollout-pkg','1.0','Queued',3)"
)->execute([':exposure'=>$exposureID,':asset'=>$assetID,':software'=>$softwareID]);
$jobID=(int)$db->lastInsertId();

$db->prepare("INSERT INTO remediation_rollout_groups (groupName,phase,canaryPercent,maxConcurrent,autoPauseOnFailure,failureThreshold) VALUES ('ci-rollout','Canary',100,1,1,1)")
    ->execute();
$groupID=(int)$db->lastInsertId();
$db->prepare('INSERT INTO asset_remediation_rollouts (assetID,groupID) VALUES (:asset,:group)')
    ->execute([':asset'=>$assetID,':group'=>$groupID]);

$claim=claimRemediationJob($db,'rollout-worker',120);
rolloutdbcheck($claim!==null && (int)$claim['jobID']===$jobID,'rollout fixture job is claimable');
$decision=remediationRolloutDecision($db,$claim);
rolloutdbcheck($decision['allowed']===true && $decision['reason']==='canary_asset_allowed','100 percent canary admits assigned asset');

$db->prepare("UPDATE remediation_rollout_groups SET phase='Paused',pausedReason='operator test' WHERE groupID=:group")
    ->execute([':group'=>$groupID]);
$paused=remediationRolloutDecision($db,$claim);
rolloutdbcheck($paused['allowed']===false && $paused['reason']==='rollout_group_paused','paused rollout blocks remote execution');
deferClaimForRemediationRollout($db,$claim,$paused,60);
$row=$db->query("SELECT status,attemptCount,nextAttemptAt,lastFailureClass FROM remediation_jobs WHERE jobID={$jobID}")->fetch();
rolloutdbcheck($row['status']==='Queued' && (int)$row['attemptCount']===0 && $row['nextAttemptAt']!==null,'rollout defer releases lease without consuming an attempt');
rolloutdbcheck($row['lastFailureClass']==='rollout_deferred','rollout defer records a distinct failure class');
rolloutdbcheck($db->query("SELECT status FROM exposure_matches WHERE exposureID={$exposureID}")->fetchColumn()==='Remediation_Queued','defer returns exposure to remediation queue');
rolloutdbcheck($db->query("SELECT status FROM asset_vulnerabilities WHERE assetVulnID={$assetVulnID}")->fetchColumn()==='Confirmed','defer returns lifecycle to Confirmed');
rolloutdbcheck((int)$db->query("SELECT COUNT(*) FROM remediation_rollout_events WHERE groupID={$groupID} AND eventType='Deferred'")->fetchColumn()===1,'defer is auditable');

$db->exec("UPDATE remediation_jobs SET nextAttemptAt=DATE_SUB(CURRENT_TIMESTAMP,INTERVAL 1 SECOND) WHERE jobID={$jobID}");
$db->prepare("UPDATE remediation_rollout_groups SET phase='General',pausedReason=NULL WHERE groupID=:group")
    ->execute([':group'=>$groupID]);
$claim2=claimRemediationJob($db,'rollout-worker-2',120);
rolloutdbcheck($claim2!==null,'general phase permits job claim');
$general=remediationRolloutDecision($db,$claim2);
rolloutdbcheck($general['allowed']===true && $general['reason']==='general_rollout_allowed','general phase passes rollout gate');
$record=recordRemediationRolloutOutcome($db,$claim2,false,'simulated post-execution failure');
rolloutdbcheck($record['auto_paused']===true,'configured failure threshold auto-pauses rollout group');
rolloutdbcheck($db->query("SELECT phase FROM remediation_rollout_groups WHERE groupID={$groupID}")->fetchColumn()==='Paused','group state is Paused after threshold failure');
rolloutdbcheck((int)$db->query("SELECT COUNT(*) FROM remediation_rollout_events WHERE groupID={$groupID} AND eventType='Auto_Paused'")->fetchColumn()===1,'auto-pause transition is auditable');

echo "PASS: {$tests} remediation rollout database tests\n";
