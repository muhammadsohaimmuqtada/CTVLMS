#!/usr/bin/env php
<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/package_advisory_guard.php';

$provider = new DebianSecurityTrackerProvider();
$fixture = null;
$allowShrink = false;
for ($i=1; $i<count($argv); $i++) {
    $arg = $argv[$i];
    if ($arg === '--allow-shrink') {
        $allowShrink = true;
        continue;
    }
    if ($arg === '--file') {
        $fixture = $argv[++$i] ?? null;
        if ($fixture === null) {
            fwrite(STDERR, "Usage: php bin/sync-package-advisories.php [--file /path/to/debian-tracker.json] [--allow-shrink]\n");
            exit(2);
        }
        continue;
    }
    fwrite(STDERR, "Usage: php bin/sync-package-advisories.php [--file /path/to/debian-tracker.json] [--allow-shrink]\n");
    exit(2);
}
if ($fixture !== null && !is_readable($fixture)) {
    fwrite(STDERR, "Advisory fixture is not readable: {$fixture}\n");
    exit(2);
}

$downloaded = false;
try {
    $path = $fixture ?? downloadAdvisoryFeed($provider->sourceUrl());
    $downloaded = $fixture === null;
    $result = ingestDistributionAdvisoriesGuarded(getDB(), $provider, $path, $allowShrink);
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (Throwable $error) {
    fwrite(STDERR, 'Package advisory sync failed: ' . $error->getMessage() . PHP_EOL);
    exit(1);
} finally {
    if ($downloaded && isset($path)) @unlink($path);
}
