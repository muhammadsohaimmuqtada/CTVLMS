#!/usr/bin/env php
<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/staging.php';

function stagingUsage(): never
{
    fwrite(STDERR, "Usage:\n");
    fwrite(STDERR, "  php bin/staging-pilot.php preflight <asset-id,asset-id[,asset-id]>\n");
    fwrite(STDERR, "  php bin/staging-pilot.php report <asset-id,asset-id[,asset-id]>\n");
    fwrite(STDERR, "  php bin/staging-pilot.php execute-gate <asset-id,asset-id[,asset-id]> <approved-job-id>\n");
    exit(2);
}

$command = $argv[1] ?? '';
$rawAssets = $argv[2] ?? '';
if (!in_array($command, ['preflight','report','execute-gate'], true) || $rawAssets === '') stagingUsage();

try {
    $assetIDs = parseStagingAssetIDs($rawAssets);
    $db = getDB();

    if ($command === 'preflight') {
        $result = stagingPrepareAssessment($db, $assetIDs);
    } elseif ($command === 'report') {
        $result = stagingFleetReport($db, $assetIDs);
    } else {
        if (!isset($argv[3]) || !preg_match('/^[1-9][0-9]*$/', $argv[3])) stagingUsage();
        $result = stagingExecutionAssessment($db, $assetIDs, (int)$argv[3]);
    }

    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), PHP_EOL;
    if (isset($result['ok']) && $result['ok'] !== true) exit(1);
} catch (Throwable $e) {
    fwrite(STDERR, json_encode([
        'ok' => false,
        'error' => $e->getMessage(),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(1);
}
