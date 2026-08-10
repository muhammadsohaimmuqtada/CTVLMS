#!/usr/bin/env php
<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/inventory.php';

$assetID = filter_var($argv[1] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
if (!$assetID) {
    fwrite(STDERR, "Usage: php bin/inventory-local.php <asset-id>\n");
    exit(2);
}

try {
    $result = collectLocalInventory(getDB(), (int)$assetID);
    logAction('INVENTORY', 'assets', (int)$assetID, 'Collected authoritative local endpoint inventory');
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (Throwable $e) {
    fwrite(STDERR, "Local inventory failed: {$e->getMessage()}\n");
    exit(1);
}
