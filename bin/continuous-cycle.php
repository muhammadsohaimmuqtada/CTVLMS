#!/usr/bin/env php
<?php
/**
 * CTVLMS — One continuous exposure-management cycle.
 *
 * Intended for cron/systemd timer execution. A cycle:
 *   1. ingests recently modified NVD CVEs,
 *   2. scans configured authorised network targets,
 *   3. correlates current inventory,
 *   4. queues policy-eligible remediation,
 *   5. optionally executes Auto jobs,
 *   6. verifies completed remediation.
 *
 * Environment:
 *   CTVLMS_SCAN_TARGETS=192.168.1.0/24,10.0.0.10
 *   CTVLMS_EXECUTE_PATCHES=1
 *   CTVLMS_MAX_PATCHES_PER_CYCLE=5
 */

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/sync_cve.php';
require_once __DIR__ . '/../includes/exposure.php';

function runChild(array $command): array
{
    $descriptor = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($command, $descriptor, $pipes);
    if (!is_resource($proc)) throw new RuntimeException('Unable to launch child process.');
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exit = proc_close($proc);
    return ['exit' => $exit, 'stdout' => trim($stdout), 'stderr' => trim($stderr)];
}

$db = getDB();
$summary = [
    'started_at' => gmdate(DATE_ATOM),
    'nvd_processed' => 0,
    'scans' => [],
    'correlation' => null,
    'jobs_queued' => 0,
    'patches' => [],
    'verification' => null,
];

$nvd = syncNistCVEs($db);
$summary['nvd_processed'] = $nvd === false ? 0 : $nvd;

$targets = array_values(array_filter(array_map('trim', explode(',', (string)getenv('CTVLMS_SCAN_TARGETS')))));
foreach ($targets as $target) {
    $result = runChild([PHP_BINARY, __DIR__ . '/scan-network.php', $target]);
    $summary['scans'][] = [
        'target' => $target,
        'ok' => $result['exit'] === 0,
        'output' => $result['exit'] === 0 ? $result['stdout'] : $result['stderr'],
    ];
}

// Re-evaluate once globally after all scans so new NVD data is applied even
// when no network scan target is configured for this cycle.
$summary['correlation'] = evaluateExposureInventory($db);
$summary['jobs_queued'] = queueEligibleRemediationJobs($db);

if (getenv('CTVLMS_EXECUTE_PATCHES') === '1') {
    $limit = max(1, min(50, (int)(getenv('CTVLMS_MAX_PATCHES_PER_CYCLE') ?: 5)));
    for ($i = 0; $i < $limit; $i++) {
        $result = runChild([PHP_BINARY, __DIR__ . '/patch-worker.php']);
        if (str_contains($result['stdout'], 'No executable remediation jobs.')) break;
        $summary['patches'][] = [
            'ok' => $result['exit'] === 0,
            'output' => $result['exit'] === 0 ? $result['stdout'] : $result['stderr'],
        ];
        if ($result['exit'] !== 0) break;
    }
}

$verification = runChild([PHP_BINARY, __DIR__ . '/verify-remediations.php']);
$summary['verification'] = [
    'ok' => $verification['exit'] === 0,
    'output' => $verification['exit'] === 0 ? $verification['stdout'] : $verification['stderr'],
];
$summary['finished_at'] = gmdate(DATE_ATOM);

logAction('CYCLE', 'exposure_matches', null, 'Continuous exposure-management cycle completed');
echo json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
