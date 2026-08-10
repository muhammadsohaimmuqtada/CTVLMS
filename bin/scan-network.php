#!/usr/bin/env php
<?php
/** Scan an authorised IP/CIDR, ingest inventory, and run correlation. */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/discovery.php';
require_once __DIR__ . '/../includes/exposure.php';

function validScanTarget(string $target): bool
{
    if (filter_var($target, FILTER_VALIDATE_IP)) return true;
    if (!preg_match('/^(.+)\/(\d{1,3})$/', $target, $m) || !filter_var($m[1], FILTER_VALIDATE_IP)) return false;
    $bits = str_contains($m[1], ':') ? 128 : 32;
    return (int)$m[2] >= 0 && (int)$m[2] <= $bits;
}

$target = trim((string)($argv[1] ?? ''));
if ($target === '' || !validScanTarget($target)) {
    fwrite(STDERR, "Usage: php bin/scan-network.php <authorised-ip-or-cidr>\n");
    exit(2);
}

$descriptor = [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']];
// Keep closed/filtered states in XML. Explicit closed-port evidence can safely
// retire an old service; filtered/unseen ports remain unknown rather than being
// converted into a false-negative inventory result.
$command = ['nmap', '-sV', '--version-light', '--reason', '-oX', '-', $target];
$process = proc_open($command, $descriptor, $pipes);
if (!is_resource($process)) {
    fwrite(STDERR, "Unable to start nmap. Ensure it is installed and available in PATH.\n");
    exit(1);
}
fclose($pipes[0]);
$xml = stream_get_contents($pipes[1]);
$stderr = stream_get_contents($pipes[2]);
fclose($pipes[1]); fclose($pipes[2]);
$exitCode = proc_close($process);
if ($exitCode !== 0 || trim($xml) === '') {
    fwrite(STDERR, "Nmap failed (exit {$exitCode}): " . trim($stderr) . "\n");
    exit(1);
}

try {
    $db = getDB();
    $import = importNmapXml($db, $xml, $target);
    $correlation = evaluateExposureInventory($db);
    $queued = queueEligibleRemediationJobs($db);
    echo json_encode([
        'scan'=>$import,
        'correlation'=>$correlation,
        'remediation_jobs_queued'=>$queued,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (Throwable $ex) {
    fwrite(STDERR, "Scan ingestion failed: {$ex->getMessage()}\n");
    exit(1);
}
