<?php
require_once __DIR__ . '/../includes/remediation_rollout.php';

$tests = 0;
function rcheck(bool $ok, string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

$bucket1 = remediationRolloutBucket(7, 42);
$bucket2 = remediationRolloutBucket(7, 42);
rcheck($bucket1 === $bucket2, 'canary bucket is deterministic');
rcheck($bucket1 >= 0 && $bucket1 <= 99, 'canary bucket is bounded');
rcheck(remediationRolloutBucket(8, 42) !== $bucket1 || remediationRolloutBucket(7, 43) !== $bucket1, 'bucket key includes group and asset');
rcheck(remediationRolloutShouldAutoPause(['autoPauseOnFailure'=>1,'failureThreshold'=>2],1) === false, 'failure threshold not reached');
rcheck(remediationRolloutShouldAutoPause(['autoPauseOnFailure'=>1,'failureThreshold'=>2],2) === true, 'failure threshold pauses rollout');
rcheck(remediationRolloutShouldAutoPause(['autoPauseOnFailure'=>0,'failureThreshold'=>1],10) === false, 'auto pause can be disabled');

echo "PASS: {$tests} remediation rollout policy tests\n";
