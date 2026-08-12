<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/inventory.php';

$tests = 0;
function inventorydbcheck(bool $ok, string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}
$db = getDB();
$db->exec("INSERT INTO assets (assetName,assetType,ipAddress,osPlatform,environment) VALUES ('remote-inventory-fixture','Server','198.51.100.60','Linux','Test')");
$assetID = (int)$db->lastInsertId();

$localFacts = linuxFactsFromObservations(
    ['ID'=>'debian','PRETTY_NAME'=>'Debian GNU/Linux 13','VERSION_ID'=>'13','VERSION_CODENAME'=>'trixie','ID_LIKE'=>'debian'],
    'remote-fixture','x86_64','6.12.1','apt'
);
$localPackages = [[
    'binary_package'=>'openssl','binary_version'=>'3.0.1-1','architecture'=>'amd64',
    'source_package'=>'openssl','source_version'=>'3.0.1-1','upstream_source_version'=>'3.0.1',
]];
$first = persistManagedInventory($db,$assetID,$localFacts,$localPackages,'Local','Local_dpkg','Local');
inventorydbcheck($first['packages']===1, 'local managed snapshot persists package');
$package = $db->query("SELECT * FROM asset_package_inventory WHERE assetID={$assetID}")->fetch();
inventorydbcheck($package['inventorySource']==='Local_dpkg' && (int)$package['isActive']===1, 'local package provenance recorded');
$oldSoftwareID = (int)$package['softwareID'];

$sshFacts = $localFacts;
$sshFacts['kernel'] = '6.12.2';
$sshPackages = [[
    'binary_package'=>'openssl','binary_version'=>'3.0.2-1','architecture'=>'amd64',
    'source_package'=>'openssl','source_version'=>'3.0.2-1','upstream_source_version'=>'3.0.2',
]];
$second = persistManagedInventory($db,$assetID,$sshFacts,$sshPackages,'SSH','SSH_dpkg','SSH');
inventorydbcheck($second['packages']===1 && $second['inventory_source']==='SSH_dpkg', 'SSH snapshot uses shared persistence path');
$rows = $db->query("SELECT * FROM asset_package_inventory WHERE assetID={$assetID}")->fetchAll();
inventorydbcheck(count($rows)===1, 'collector transition does not duplicate package identity');
inventorydbcheck($rows[0]['inventorySource']==='SSH_dpkg' && $rows[0]['binaryVersion']==='3.0.2-1', 'latest authoritative collector and version replace prior state');
$newSoftwareID = (int)$rows[0]['softwareID'];
inventorydbcheck($newSoftwareID!==$oldSoftwareID, 'package version change points identity to new software observation');
inventorydbcheck((int)$db->query("SELECT isActive FROM asset_software WHERE softwareID={$oldSoftwareID}")->fetchColumn()===0, 'superseded managed software row is inactive');
inventorydbcheck((int)$db->query("SELECT isActive FROM asset_software WHERE softwareID={$newSoftwareID}")->fetchColumn()===1, 'current managed software row is active');
inventorydbcheck((int)$db->query("SELECT COUNT(*) FROM asset_facts WHERE assetID={$assetID} AND source='SSH' AND factKey='kernel' AND factValue='6.12.2'")->fetchColumn()===1, 'SSH facts retain collection provenance');
inventorydbcheck((int)$db->query("SELECT COUNT(*) FROM asset_platform_cpes WHERE assetID={$assetID} AND source='SSH' AND isActive=1")->fetchColumn()===1, 'SSH platform evidence is active');

$failed = false;
try { persistManagedInventory($db,$assetID,$sshFacts,[],'SSH','SSH_dpkg','SSH'); }
catch (RuntimeException) { $failed = true; }
inventorydbcheck($failed, 'empty authoritative apt snapshot cannot retire current package inventory');
inventorydbcheck((int)$db->query("SELECT COUNT(*) FROM asset_package_inventory WHERE assetID={$assetID} AND isActive=1")->fetchColumn()===1, 'failed empty snapshot leaves prior inventory active');

echo "PASS: {$tests} remote inventory database tests\n";
