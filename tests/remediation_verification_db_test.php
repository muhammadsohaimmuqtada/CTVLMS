<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/inventory.php';
require_once __DIR__ . '/../includes/package_engine_v2.php';
require_once __DIR__ . '/../includes/verification.php';

$tests=0;
function verifydbcheck(bool $ok,string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR,"FAIL: {$message}\n"); exit(1); }
}
$db=getDB();
$db->exec("INSERT INTO assets (assetName,assetType,ipAddress,osPlatform,environment) VALUES ('verify-package-fixture','Server','198.51.100.80','Debian','Test')");
$assetID=(int)$db->lastInsertId();
$facts=linuxFactsFromObservations(
    ['ID'=>'debian','PRETTY_NAME'=>'Debian GNU/Linux','VERSION_ID'=>'sid','VERSION_CODENAME'=>'sid','ID_LIKE'=>'debian'],
    'verify-fixture','x86_64','6.12.0','apt'
);
$beforePackages=[[
    'binary_package'=>'verify-pkg','binary_version'=>'1.0-1','architecture'=>'amd64',
    'source_package'=>'verify-pkg','source_version'=>'1.0-1','upstream_source_version'=>'1.0',
]];
persistManagedInventory($db,$assetID,$facts,$beforePackages,'Local','Local_dpkg','Local');
$softwareID=(int)$db->query("SELECT softwareID FROM asset_package_inventory WHERE assetID={$assetID} AND binaryPackage='verify-pkg' AND isActive=1")->fetchColumn();

$db->exec("INSERT INTO vulnerabilities (cveID,title,description,cvssScore,severity,publishedDate) VALUES ('CVE-2096-8000','Package verification fixture','fixture',7.0,'High',CURDATE())");
$vulnID=(int)$db->lastInsertId();
$db->prepare(
    "INSERT INTO distribution_advisories
        (recordKey,advisoryIdentifier,cveID,distribution,suite,sourcePackage,state,fixedVersion,
         sourceUrl,dataSourceIdentifier,provider,providerRecordJson)
     VALUES (:key,'CVE-2096-8000','CVE-2096-8000','debian','sid','verify-pkg','Fixed','2.0-1',
             'https://security-tracker.debian.org/tracker/data/json','verify-fixture','DebianSecurityTracker','{}')"
)->execute([':key'=>hash('sha256','verify-package-advisory')]);
$result=evaluatePackageAdvisoriesV2($db,$assetID);
verifydbcheck($result['confirmed']===1, 'pre-remediation package is authoritatively confirmed vulnerable');
$exposure=$db->query("SELECT * FROM exposure_matches WHERE assetID={$assetID} AND matchType='Package_Advisory' LIMIT 1")->fetch();
verifydbcheck((bool)$exposure, 'package advisory exposure materialized');
$exposureID=(int)$exposure['exposureID'];
$assetVulnID=(int)$db->query("SELECT assetVulnID FROM asset_vulnerabilities WHERE assetID={$assetID} AND vulnID={$vulnID}")->fetchColumn();
$db->prepare(
    "INSERT INTO remediations (assetVulnID,actionTaken,remediationType,startedDate,completedDate)
     VALUES (:assetVuln,'fixture package upgrade','Patch',CURDATE(),CURDATE())"
)->execute([':assetVuln'=>$assetVulnID]);
$remediationID=(int)$db->lastInsertId();
$db->prepare(
    "INSERT INTO remediation_jobs
        (exposureID,assetID,softwareID,remediationID,packageManager,packageName,fromVersion,targetVersion,status,requestedAt,startedAt,completedAt,attemptCount)
     VALUES (:exposure,:asset,:software,:remediation,'apt','verify-pkg','1.0-1','2.0-1','Succeeded',
             DATE_SUB(CURRENT_TIMESTAMP,INTERVAL 2 MINUTE),DATE_SUB(CURRENT_TIMESTAMP,INTERVAL 2 MINUTE),
             DATE_SUB(CURRENT_TIMESTAMP,INTERVAL 1 MINUTE),1)"
)->execute([':exposure'=>$exposureID,':asset'=>$assetID,':software'=>$softwareID,':remediation'=>$remediationID]);
$db->prepare("UPDATE exposure_matches SET status='Remediated' WHERE exposureID=:id")->execute([':id'=>$exposureID]);
$db->prepare("UPDATE asset_vulnerabilities SET status='Remediated' WHERE assetVulnID=:id")->execute([':id'=>$assetVulnID]);

verifydbcheck(verifyRemediatedExposure($db,$exposureID)===false, 'closure waits for a successful inventory run newer than the patch');
verifydbcheck($db->query("SELECT status FROM exposure_matches WHERE exposureID={$exposureID}")->fetchColumn()==='Remediated', 'pending verification does not invent closure');

$afterPackages=[[
    'binary_package'=>'verify-pkg','binary_version'=>'2.0-1','architecture'=>'amd64',
    'source_package'=>'verify-pkg','source_version'=>'2.0-1','upstream_source_version'=>'2.0',
]];
persistManagedInventory($db,$assetID,$facts,$afterPackages,'SSH','SSH_dpkg','SSH');
$db->prepare(
    "INSERT INTO inventory_runs (assetID,transport,inventorySource,status,factsObserved,packagesObserved,startedAt,completedAt)
     VALUES (:asset,'SSH','SSH_dpkg','Succeeded',10,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"
)->execute([':asset'=>$assetID]);

verifydbcheck(verifyRemediatedExposure($db,$exposureID)===true, 'fresh authoritative fixed package inventory closes remediation');
verifydbcheck($db->query("SELECT status FROM exposure_matches WHERE exposureID={$exposureID}")->fetchColumn()==='Verified_Closed', 'package exposure becomes Verified_Closed');
verifydbcheck($db->query("SELECT status FROM asset_vulnerabilities WHERE assetVulnID={$assetVulnID}")->fetchColumn()==='Verified_Closed', 'asset vulnerability lifecycle closes');
verifydbcheck((int)$db->query("SELECT COUNT(*) FROM remediation_verifications WHERE remediationID={$remediationID}")->fetchColumn()===1, 'automated verification evidence is persisted');
$evidence=json_decode((string)$db->query("SELECT evidence FROM remediation_verifications WHERE remediationID={$remediationID}")->fetchColumn(),true);
verifydbcheck(($evidence['result'] ?? '')==='package_not_affected_after_remediation', 'verification evidence records package applicability result');

echo "PASS: {$tests} remediation verification database tests\n";
