#!/usr/bin/env php
<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/package_advisories.php';

$provider = new DebianSecurityTrackerProvider();
$fixture = null;
if (($argv[1] ?? '') === '--file') $fixture = $argv[2] ?? null;
if ($fixture !== null && !is_readable($fixture)) {
    fwrite(STDERR, "Usage: php bin/sync-package-advisories.php [--file /path/to/debian-tracker.json]\n");
    exit(2);
}
$downloaded = false;
try {
    $path = $fixture ?? downloadAdvisoryFeed($provider->sourceUrl());
    $downloaded = $fixture === null;
    $result = ingestDistributionAdvisories(getDB(), $provider, $path);
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (Throwable $error) {
    fwrite(STDERR, 'Package advisory sync failed: ' . $error->getMessage() . PHP_EOL);
    exit(1);
} finally {
    if ($downloaded && isset($path)) @unlink($path);
}
