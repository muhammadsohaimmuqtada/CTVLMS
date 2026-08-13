<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';

$tests=0;
function statedbcheck(bool $ok,string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR,"FAIL: {$message}\n"); exit(1); }
}

$db=getDB();
$db->exec("INSERT INTO assets (assetName,assetType,ipAddress,osPlatform,environment) VALUES ('state-guard-fixture','Server','198.51.100.91','Debian','Test')");
$assetID=(int)$db->lastInsertId();
$db->exec("INSERT INTO vulnerabilities (cveID,title,description,cvssScore,severity,publishedDate) VALUES ('CVE-2096-9100','State guard fixture','fixture',5.0,'Medium',CURDATE())");
$vulnID=(int)$db->lastInsertId();
$db->prepare("INSERT INTO asset_software (assetID,product,version,packageManager,packageName,source,isActive) VALUES (:asset,'state-pkg','1.0','apt','state-pkg','Agent',1)")->execute([':asset'=>$assetID]);
$softwareID=(int)$db->lastInsertId();
$db->prepare("INSERT INTO asset_vulnerabilities (assetID,vulnID,status,discoveredDate) VALUES (:asset,:vuln,'Remediated',CURDATE())")->execute([':asset'=>$assetID,':vuln'=>$vulnID]);
$assetVulnID=(int)$db->lastInsertId();

$key=hash('sha256','state-guard-fixture');
$db->prepare(
    "INSERT INTO exposure_matches (matchKey,assetID,vulnID,softwareID,matchType,confidence,status,evidence)
     VALUES (:key,:asset,:vuln,:software,'CPE_Exact',0.99,'Remediated','{}')"
)->execute([':key'=>$key,':asset'=>$assetID,':vuln'=>$vulnID,':software'=>$softwareID]);
$exposureID=(int)$db->lastInsertId();

$db->prepare("UPDATE exposure_matches SET status='Not_Affected' WHERE exposureID=:id")->execute([':id'=>$exposureID]);
statedbcheck($db->query("SELECT status FROM exposure_matches WHERE exposureID={$exposureID}")->fetchColumn()==='Remediated', 'correlation cannot erase Remediated before verification');

$db->prepare("UPDATE exposure_matches SET status='Verified_Closed' WHERE exposureID=:id")->execute([':id'=>$exposureID]);
$db->prepare("UPDATE asset_vulnerabilities SET status='Verified_Closed',closedDate=CURDATE() WHERE assetVulnID=:id")->execute([':id'=>$assetVulnID]);
statedbcheck($db->query("SELECT status FROM exposure_matches WHERE exposureID={$exposureID}")->fetchColumn()==='Verified_Closed', 'verification may transition Remediated to Verified_Closed');

$db->prepare("UPDATE exposure_matches SET status='Not_Affected' WHERE exposureID=:id")->execute([':id'=>$exposureID]);
statedbcheck($db->query("SELECT status FROM exposure_matches WHERE exposureID={$exposureID}")->fetchColumn()==='Verified_Closed', 'stable Not_Affected evidence preserves Verified_Closed');
statedbcheck($db->query("SELECT status FROM asset_vulnerabilities WHERE assetVulnID={$assetVulnID}")->fetchColumn()==='Verified_Closed', 'stable evidence keeps lifecycle closed');

$db->prepare("UPDATE exposure_matches SET status='Confirmed' WHERE exposureID=:id")->execute([':id'=>$exposureID]);
statedbcheck($db->query("SELECT status FROM exposure_matches WHERE exposureID={$exposureID}")->fetchColumn()==='Verification_Failed', 'contradictory evidence reopens Verified_Closed as Verification_Failed');
$lifecycle=$db->query("SELECT status,closedDate,notes FROM asset_vulnerabilities WHERE assetVulnID={$assetVulnID}")->fetch();
statedbcheck($lifecycle['status']==='Confirmed' && $lifecycle['closedDate']===null, 'contradictory evidence reopens asset lifecycle and clears closed date');
statedbcheck(str_contains((string)$lifecycle['notes'],'contradicted verified closure'), 'lifecycle reopen records an operator-readable reason');

$db->prepare("UPDATE exposure_matches SET status='Remediation_Queued' WHERE exposureID=:id")->execute([':id'=>$exposureID]);
$db->prepare(
    "INSERT INTO remediation_jobs (exposureID,assetID,softwareID,packageManager,packageName,fromVersion,status)
     VALUES (:exposure,:asset,:software,'apt','state-pkg','1.0','Queued')"
)->execute([':exposure'=>$exposureID,':asset'=>$assetID,':software'=>$softwareID]);
$jobID=(int)$db->lastInsertId();
$db->prepare("UPDATE exposure_matches SET status='Not_Affected' WHERE exposureID=:id")->execute([':id'=>$exposureID]);
statedbcheck($db->query("SELECT status FROM exposure_matches WHERE exposureID={$exposureID}")->fetchColumn()==='Not_Affected', 'queued exposure may resolve to Not_Affected');
$job=$db->query("SELECT status,lastFailureClass,lastError FROM remediation_jobs WHERE jobID={$jobID}")->fetch();
statedbcheck($job['status']==='Cancelled', 'obsolete queued remediation is Cancelled rather than left stuck');
statedbcheck($job['lastFailureClass']==='applicability_changed', 'cancelled job records applicability_changed classification');
statedbcheck(str_contains((string)$job['lastError'],'Not_Affected'), 'cancelled job records operator-readable reason');

echo "PASS: {$tests} remediation state guard database tests\n";
