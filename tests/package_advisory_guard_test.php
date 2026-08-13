<?php
require_once __DIR__ . '/../includes/package_advisory_guard_v2.php';

$tests = 0;
function gcheck(bool $ok, string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

assertAdvisorySnapshotIsSane(1000, 0, false, 1000, 0.60);
gcheck(true, 'first snapshot is allowed');
assertAdvisorySnapshotIsSane(800, 1000, false, 100, 0.60);
gcheck(true, 'reasonable snapshot shrink is allowed');

$failed = false;
try { assertAdvisorySnapshotIsSane(500, 1000, false, 100, 0.60); }
catch (RuntimeException $e) { $failed = str_contains($e->getMessage(), 'snapshot rejected'); }
gcheck($failed, 'ratio guard rejects anomalous shrink');

$failed = false;
try { assertAdvisorySnapshotIsSane(50, 1000, false, 100, 0.01); }
catch (RuntimeException $e) { $failed = str_contains($e->getMessage(), 'below minimum'); }
gcheck($failed, 'absolute minimum rejects tiny replacement');

assertAdvisorySnapshotIsSane(1, 1000, true, 100, 0.90);
gcheck(true, 'explicit override permits intentional shrink');

echo "PASS: {$tests} advisory snapshot guard tests\n";
