<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/discovery.php';
require_once __DIR__ . '/../includes/exposure.php';

$db = getDB();
$tests = 0;
function it(bool $ok, string $message): void { global $tests; $tests++; if (!$ok) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$db->exec('SET FOREIGN_KEY_CHECKS=0');
foreach (['remediation_jobs','exposure_matches','vulnerability_configurations','vulnerability_cpe_matches','asset_platform_cpes','asset_facts','asset_services','asset_software','asset_vulnerabilities','scan_runs','vulnerabilities','assets','audit_log'] as $table) $db->exec("TRUNCATE TABLE {$table}");
$db->exec('SET FOREIGN_KEY_CHECKS=1');

$xml1 = '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><hostnames><hostname name="localhost"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="10.3"/></port><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.68"><cpe>cpe:/a:apache:http_server:2.4.68</cpe></service></port></ports></host></nmaprun>';
$r1 = importNmapXml($db, $xml1, '127.0.0.1');
it($r1['services'] === 2, 'first scan imports two services');
$assetID = (int)$db->query("SELECT assetID FROM assets WHERE ipAddress='127.0.0.1'")->fetchColumn();

$xml2 = '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.68"><cpe>cpe:/a:apache:http_server:2.4.68</cpe></service></port></ports></host></nmaprun>';
$r2 = importNmapXml($db, $xml2, '127.0.0.1');
it($r2['services_retired'] === 1, 'second scan retires disappeared service');
it((int)$db->query("SELECT isActive FROM asset_services WHERE assetID={$assetID} AND port=22")->fetchColumn() === 0, 'port 22 is inactive');

$db->prepare("INSERT INTO asset_platform_cpes (assetID,cpe,source) VALUES (:a,'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*','Test')")->execute([':a'=>$assetID]);
$db->exec("INSERT INTO vulnerabilities (cveID,title,description,cvssScore,severity) VALUES ('CVE-2099-0001','Compound Apache Windows test','test',8.0,'High')");
$vulnID = (int)$db->lastInsertId();
$db->prepare("INSERT INTO vulnerability_cpe_matches (vulnID,criteria,vulnerable,configurationComplex,source) VALUES (:v,'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*',1,1,'NVD')")->execute([':v'=>$vulnID]);
$config = [['operator'=>'AND','nodes'=>[
    ['operator'=>'OR','cpeMatch'=>[['vulnerable'=>true,'criteria'=>'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*','versionEndIncluding'=>'2.4.68']]],
    ['operator'=>'OR','cpeMatch'=>[['vulnerable'=>false,'criteria'=>'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*']]],
]]];
$db->prepare("INSERT INTO vulnerability_configurations (vulnID,configIndex,configurationJson,source) VALUES (:v,0,:j,'NVD')")->execute([':v'=>$vulnID,':j'=>json_encode($config[0], JSON_UNESCAPED_SLASHES)]);
$result = evaluateExposureInventory($db, $assetID);
it($result['not_affected'] === 1, 'Linux platform makes Windows-only compound CVE not affected');
it((int)$db->query("SELECT COUNT(*) FROM asset_vulnerabilities WHERE assetID={$assetID} AND vulnID={$vulnID}")->fetchColumn() === 0, 'not affected result does not create lifecycle finding');

$db->prepare("UPDATE asset_platform_cpes SET isActive=0 WHERE assetID=:a")->execute([':a'=>$assetID]);
$db->prepare("INSERT INTO asset_platform_cpes (assetID,cpe,source) VALUES (:a,'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*','Test')")->execute([':a'=>$assetID]);
$result2 = evaluateExposureInventory($db, $assetID);
it($result2['confirmed'] === 1, 'evidence change reopens same exposure as confirmed');
it((int)$db->query("SELECT COUNT(*) FROM asset_vulnerabilities WHERE assetID={$assetID} AND vulnID={$vulnID}")->fetchColumn() === 1, 'confirmed applicability creates lifecycle finding');

echo "PASS: {$tests} database integration tests\n";
