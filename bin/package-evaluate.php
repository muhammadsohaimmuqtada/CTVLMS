#!/usr/bin/env php
<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/package_evaluator.php';

$assetID = null;
if (isset($argv[1])) {
    $assetID = filter_var($argv[1], FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
    if ($assetID === false) {
        fwrite(STDERR, "Usage: php bin/package-evaluate.php [asset-id]\n");
        exit(2);
    }
}

try {
    echo json_encode(
        evaluatePackageAdvisoriesScalable(getDB(), $assetID === null ? null : (int)$assetID),
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
    ) . PHP_EOL;
} catch (Throwable $error) {
    fwrite(STDERR, 'Package evaluation failed: ' . $error->getMessage() . PHP_EOL;
    exit(1);
}
