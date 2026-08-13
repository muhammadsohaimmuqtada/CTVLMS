#!/usr/bin/env php
<?php
require_once __DIR__ . '/../includes/production.php';
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/health.php';

$result = ctvlmsProductionChecks(ctvlmsCurrentEnvironment());
try {
    $result['database'] = ctvlmsReadiness(getDB());
    if (($result['database']['status'] ?? '') !== 'ok') {
        $result['ok'] = false;
        $result['errors'][] = 'Database readiness check failed.';
    }
} catch (Throwable) {
    $result['database'] = ['status'=>'unavailable'];
    $result['ok'] = false;
    $result['errors'][] = 'Database readiness check failed.';
}

echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
exit($result['ok'] ? 0 : 1);
