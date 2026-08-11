<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/discovery.php';
require_once __DIR__ . '/../includes/exposure.php';
require_once __DIR__ . '/../includes/package_advisories.php';

$tests = 0;
function dbcheck(bool $ok, string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}
$db = getDB();

$xml1 = <<<'XML'
<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><hostnames><hostname name="test-host"/></hostnames><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.9"><cpe>cpe:/a:openbsd:openssh:9.9</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.68"><cpe>cpe:/a:apache:http_server:2.4.68</cpe></service></port>
</ports></host></nmaprun>
XML;
$r1 = importNmapXml($db, $xml1, '192.0.2.10');
dbcheck($r1['hosts'] === 1 && $r1['services'] === 2, 'first scan imports host and two services');
$assetID = (int)$db->query("SELECT assetID FROM assets WHERE ipAddress='192.0.2.10'")->fetchColumn();
dbcheck($assetID > 0, 'asset created');
dbcheck((int)$db->query("SELECT COUNT(*) FROM asset_services WHERE assetID={$assetID} AND isActive=1")->fetchColumn() === 2, 'two active services after first scan');

$xml2 = <<<'XML'
<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><hostnames><hostname name="test-host"/></hostnames><ports>
<port protocol="tcp" portid="22"><state state="closed"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.68"><cpe>cpe:/a:apache:http_server:2.4.68</cpe></service></port>
</ports></host></nmaprun>
XML;
$r2 = importNmapXml($db, $xml2, '192.0.2.10');
dbcheck($r2['services'] === 1 && $r2['services_retired'] === 1, 'explicit closed-port evidence retires service');
dbcheck((int)$db->query("SELECT isActive FROM asset_services WHERE assetID={$assetID} AND port=22")->fetchColumn() === 0, 'closed port 22 is inactive');

$db->exec("UPDATE asset_services SET isActive=1, state='open' WHERE assetID={$assetID} AND port=22");
$xmlFiltered = <<<'XML'
<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="filtered"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.68"><cpe>cpe:/a:apache:http_server:2.4.68</cpe></service></port>
</ports></host></nmaprun>
XML;
$rFiltered = importNmapXml($db, $xmlFiltered, '192.0.2.10');
dbcheck($rFiltered['services_retired'] === 0, 'filtered port is not evidence of service absence');
dbcheck((int)$db->query("SELECT isActive FROM asset_services WHERE assetID={$assetID} AND port=22")->fetchColumn() === 1, 'filtered service remains active/stale');
$db->exec("UPDATE asset_services SET isActive=0, state='closed' WHERE assetID={$assetID} AND port=22");

$db->prepare("INSERT INTO asset_platform_cpes (assetID,cpe,source,isActive) VALUES (:asset,'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*','Agent',1)")->execute([':asset'=>$assetID]);
$db->prepare("INSERT INTO vulnerabilities (cveID,title,description,cvssScore,severity,publishedDate) VALUES ('CVE-2099-0001','Compound applicability test','CI fixture',8.0,'High',CURDATE())")->execute();
$vulnID = (int)$db->lastInsertId();
$db->prepare("INSERT INTO vulnerability_cpe_matches (vulnID,criteria,vulnerable,configurationComplex,versionStartIncluding,versionStartExcluding,versionEndIncluding,versionEndExcluding,source) VALUES (:v,'cpe:2.3:a:apache:http_server:2.4.68:*:*:*:*:*:*:*',1,1,NULL,NULL,NULL,NULL,'NVD')")->execute([':v'=>$vulnID]);
$config = [[
    'operator'=>'AND',
    'nodes'=>[
        ['operator'=>'OR','cpeMatch'=>[['vulnerable'=>true,'criteria'=>'cpe:2.3:a:apache:http_server:2.4.68:*:*:*:*:*:*:*']]],
        ['operator'=>'OR','cpeMatch'=>[['vulnerable'=>false,'criteria'=>'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*']]],
    ],
]];
$db->prepare("INSERT INTO vulnerability_configurations (vulnID,configIndex,configurationJson,source) VALUES (:v,0,:json,'NVD')")->execute([':v'=>$vulnID,':json'=>json_encode($config[0],JSON_UNESCAPED_SLASHES)]);

$linux = evaluateExposureInventory($db, $assetID);
dbcheck($linux['not_affected'] === 1, 'Linux platform rejects Windows-only applicability');
$status = $db->query("SELECT status FROM exposure_matches WHERE assetID={$assetID} AND vulnID={$vulnID}")->fetchColumn();
dbcheck($status === 'Not_Affected', 'exposure stored as Not_Affected');
dbcheck((int)$db->query("SELECT COUNT(*) FROM asset_vulnerabilities WHERE assetID={$assetID} AND vulnID={$vulnID}")->fetchColumn() === 0, 'Not_Affected does not enter lifecycle');

$db->prepare('UPDATE asset_platform_cpes SET isActive=0 WHERE assetID=:asset')->execute([':asset'=>$assetID]);
$db->prepare("INSERT INTO asset_platform_cpes (assetID,cpe,source,isActive) VALUES (:asset,'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*','Agent',1)")->execute([':asset'=>$assetID]);
$windows = evaluateExposureInventory($db, $assetID);
dbcheck($windows['confirmed'] === 1, 'Windows platform satisfies compound applicability');
$status = $db->query("SELECT status FROM exposure_matches WHERE assetID={$assetID} AND vulnID={$vulnID}")->fetchColumn();
dbcheck($status === 'Confirmed', 'Not_Affected exposure can reopen when evidence changes');
dbcheck((int)$db->query("SELECT COUNT(*) FROM asset_vulnerabilities WHERE assetID={$assetID} AND vulnID={$vulnID}")->fetchColumn() === 1, 'Confirmed exposure enters lifecycle');

// Authoritative package identity -> distro advisory -> explainable package exposure.
$db->prepare("INSERT INTO asset_facts (assetID,factKey,factValue,source,confidence) VALUES (:asset,'os_id','debian','Local',1) ON DUPLICATE KEY UPDATE factValue='debian'")->execute([':asset'=>$assetID]);
$db->prepare("INSERT INTO asset_facts (assetID,factKey,factValue,source,confidence) VALUES (:asset,'distribution_suite','bullseye','Local',1) ON DUPLICATE KEY UPDATE factValue='bullseye'")->execute([':asset'=>$assetID]);
$software = $db->prepare("INSERT INTO asset_software (assetID,product,version,packageManager,packageName,source,isActive) VALUES (:asset,'jq','1.5+dfsg-1','apt','jq','Agent',1)");
$software->execute([':asset'=>$assetID]); $softwareID = (int)$db->lastInsertId();
$package = $db->prepare("INSERT INTO asset_package_inventory (softwareID,assetID,binaryPackage,binaryVersion,architecture,sourcePackage,sourceVersion,upstreamSourceVersion,packageManager,inventorySource,identityAuthoritative,isActive) VALUES (:software,:asset,'jq','1.5+dfsg-1','amd64','jq','1.5+dfsg-1','1.5','apt','Local_dpkg',1,1)");
$package->execute([':software'=>$softwareID,':asset'=>$assetID]);
$sync = ingestDistributionAdvisories($db, new DebianSecurityTrackerProvider(), __DIR__ . '/fixtures/debian_tracker.json');
dbcheck($sync['processed'] === 6, 'fixture advisory records ingested transactionally');
$packageResult = evaluatePackageAdvisories($db, $assetID);
dbcheck($packageResult['packages_evaluated'] === 1 && $packageResult['confirmed'] === 2, 'package advisory engine evaluates fixed and open rules');
dbcheck($packageResult['not_affected'] === 2 && $packageResult['unknown'] === 1, 'package advisory states remain tri-state');
$coverage = $packageResult['coverage'];
dbcheck($coverage['packages_discovered'] === 1 && $coverage['packages_with_source_identity'] === 1 && $coverage['packages_evaluated'] === 1, 'package coverage reports discovery, identity, and evaluation separately');
dbcheck($coverage['packages_with_advisory_coverage'] === 1 && $coverage['confirmed_vulnerable'] === 1, 'package coverage reports advisory coverage and confirmed package');
$evidenceJson = $db->query("SELECT evidence FROM exposure_matches WHERE softwareID={$softwareID} AND matchType='Package_Advisory' AND status='Confirmed' ORDER BY exposureID LIMIT 1")->fetchColumn();
$packageEvidence = json_decode((string)$evidenceJson, true);
dbcheck($packageEvidence['binary_package'] === 'jq' && $packageEvidence['source_package'] === 'jq', 'package exposure evidence includes binary/source identity');
dbcheck($packageEvidence['provider'] === 'DebianSecurityTracker' && isset($packageEvidence['comparison_result']), 'package exposure evidence includes provider and comparison');
$db->prepare("INSERT INTO asset_patch_policies (assetID,mode,requireVerifiedBackup,transport) VALUES (:asset,'Approval',0,'None')")->execute([':asset'=>$assetID]);
$db->prepare('UPDATE asset_package_inventory SET identityAuthoritative=0 WHERE softwareID=:software')->execute([':software'=>$softwareID]);
dbcheck(queueEligibleRemediationJobs($db, $assetID) === 0, 'non-authoritative package identity cannot queue remediation');
$db->prepare('UPDATE asset_package_inventory SET identityAuthoritative=1 WHERE softwareID=:software')->execute([':software'=>$softwareID]);

// Kali packages may correlate to Debian source records, but never inherit a
// definitive Debian result without an explicit provenance mapping.
$db->prepare("INSERT INTO assets (assetName,assetType,ipAddress,osPlatform) VALUES ('kali-fixture','Workstation','192.0.2.11','Kali Rolling')")->execute();
$kaliAsset = (int)$db->lastInsertId();
foreach (['os_id'=>'kali','distribution_suite'=>'kali-rolling'] as $key=>$value) {
    $db->prepare("INSERT INTO asset_facts (assetID,factKey,factValue,source,confidence) VALUES (:asset,:key,:value,'Local',1)")->execute([':asset'=>$kaliAsset,':key'=>$key,':value'=>$value]);
}
$db->prepare("INSERT INTO asset_software (assetID,product,version,packageManager,packageName,source,isActive) VALUES (:asset,'jq','1.7-1+kali1','apt','jq','Agent',1)")->execute([':asset'=>$kaliAsset]);
$kaliSoftware = (int)$db->lastInsertId();
$db->prepare("INSERT INTO asset_package_inventory (softwareID,assetID,binaryPackage,binaryVersion,architecture,sourcePackage,sourceVersion,upstreamSourceVersion,packageManager,inventorySource,identityAuthoritative,isActive) VALUES (:software,:asset,'jq','1.7-1+kali1','amd64','jq','1.7-1+kali1','1.7','apt','Local_dpkg',1,1)")->execute([':software'=>$kaliSoftware,':asset'=>$kaliAsset]);
$kaliResult = evaluatePackageAdvisories($db, $kaliAsset);
dbcheck($kaliResult['confirmed'] === 0 && $kaliResult['not_affected'] === 0 && $kaliResult['unknown'] > 0, 'Kali divergence only produces Potential package exposures');
$db->prepare("INSERT INTO asset_patch_policies (assetID,mode,requireVerifiedBackup,transport) VALUES (:asset,'Approval',0,'None')")->execute([':asset'=>$kaliAsset]);
dbcheck(queueEligibleRemediationJobs($db, $kaliAsset) === 0, 'Potential and Unknown package exposures never queue remediation');

echo "PASS: {$tests} database integration tests\n";
