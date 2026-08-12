<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/remediation_queue.php';

$tests=0;
function leasecheck(bool $ok,string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR,"FAIL: {$message}\n"); exit(1); }
}
$db=getDB();
$db->exec("INSERT INTO assets (assetName,assetType,ipAddress,osPlatform,environment) VALUES ('lease-fixture','Server','198.51.100.70','Debian','Test')");
$assetID=(int)$db->lastInsertId();
$db->exec("INSERT INTO vulnerabilities (cveID,title,description,cvssScore,severity,publishedDate) VALUES ('CVE-2096-7000','Lease fixture','fixture',7.0,'High',CURDATE())");
$vulnID=(int)$db->lastInsertId();
$db->prepare("INSERT INTO asset_vulnerabilities (assetID,vulnID,status,discoveredDate) VALUES (:asset,:vuln,'Confirmed',CURDATE())")
    ->execute([':asset'=>$assetID,':vuln'=>$vulnID]);
$db->prepare("INSERT INTO asset_software (assetID,product,version,cpe,packageManager,packageName,source,isActive) VALUES (:asset,'lease-pkg','1.0','cpe:2.3:a:example:lease-pkg:1.0:*:*:*:*:*:*:*','apt','lease-pkg','Agent',1)")
    ->execute([':asset'=>$assetID]);
$softwareID=(int)$db->lastInsertId();
$db->prepare("INSERT INTO exposure_matches (matchKey,assetID,vulnID,softwareID,matchType,confidence,status,evidence) VALUES (:key,:asset,:vuln,:software,'CPE_Exact',0.99,'Remediation_Queued','{}')")
    ->execute([':key'=>hash('sha256','lease-fixture'),':asset'=>$assetID,':vuln'=>$vulnID,':software'=>$softwareID]);
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
     VALUES (:exposure,:asset,:software,'apt','lease-pkg','1.0','Queued',3)"
)->execute([':exposure'=>$exposureID,':asset'=>$assetID,':software'=>$softwareID]);
$jobID=(int)$db->lastInsertId();

$first=claimRemediationJob($db,'worker-a',120);
leasecheck($first!==null && (int)$first['jobID']===$jobID, 'first worker claims queued job');
leasecheck($first['attemptCount']===1 && strlen($first['leaseToken'])===64, 'claim assigns fenced token and attempt');
leasecheck($db->query("SELECT status FROM remediation_jobs WHERE jobID={$jobID}")->fetchColumn()==='Running', 'claimed job becomes Running');
leasecheck(claimRemediationJob($db,'worker-b',120)===null, 'active lease prevents a second worker claim');
heartbeatRemediationLease($db,$jobID,$first['leaseToken'],120);
leasecheck($db->query("SELECT lastHeartbeatAt IS NOT NULL FROM remediation_jobs WHERE jobID={$jobID}")->fetchColumn()==1, 'lease heartbeat is persisted');

$db->exec("UPDATE remediation_jobs SET leasedUntil=DATE_SUB(CURRENT_TIMESTAMP,INTERVAL 1 SECOND) WHERE jobID={$jobID}");
$second=claimRemediationJob($db,'worker-b',120);
leasecheck($second!==null && !empty($second['reclaimedExpiredLease']), 'expired running lease is recoverable');
leasecheck($second['attemptCount']===2 && $second['leaseToken']!==$first['leaseToken'], 'reclaim rotates fence token and increments attempt');
$oldFenced=false;
try { heartbeatRemediationLease($db,$jobID,$first['leaseToken'],120); }
catch (RuntimeException) { $oldFenced=true; }
leasecheck($oldFenced, 'stale worker token is fenced after recovery');

$retry=failOrRetryRemediationJob($db,$second,'temporary preflight failure','preflight_transport',true);
leasecheck($retry['retry_scheduled']===true && $retry['delay_seconds']===60, 'second-attempt transient failure schedules bounded backoff');
$row=$db->query("SELECT status,nextAttemptAt,lastFailureClass FROM remediation_jobs WHERE jobID={$jobID}")->fetch();
leasecheck($row['status']==='Queued' && $row['nextAttemptAt']!==null && $row['lastFailureClass']==='preflight_transport', 'retry clears lease and records failure class');
leasecheck(claimRemediationJob($db,'worker-c',120)===null, 'nextAttemptAt prevents immediate retry storm');
$db->exec("UPDATE remediation_jobs SET nextAttemptAt=DATE_SUB(CURRENT_TIMESTAMP,INTERVAL 1 SECOND) WHERE jobID={$jobID}");
$third=claimRemediationJob($db,'worker-c',120);
leasecheck($third!==null && $third['attemptCount']===3, 'job can be retried when backoff expires');
$final=failOrRetryRemediationJob($db,$third,'still unavailable','preflight_transport',true);
leasecheck($final['retry_scheduled']===false, 'max attempt boundary stops retrying');
$row=$db->query("SELECT status,leaseToken,workerID FROM remediation_jobs WHERE jobID={$jobID}")->fetch();
leasecheck($row['status']==='Failed' && $row['leaseToken']===null && $row['workerID']===null, 'terminal failure releases worker lease');
leasecheck($db->query("SELECT status FROM exposure_matches WHERE exposureID={$exposureID}")->fetchColumn()==='Confirmed', 'terminal preflight failure returns exposure to Confirmed');

echo "PASS: {$tests} remediation lease database tests\n";
