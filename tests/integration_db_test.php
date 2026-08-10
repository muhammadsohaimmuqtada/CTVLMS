<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/discovery.php';
require_once __DIR__ . '/../includes/exposure.php';

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

echo "PASS: {$tests} database integration tests\n";
