<?php
require_once __DIR__ . '/../includes/staging.php';

$tests = 0;
function stagingCheck(bool $condition, string $message): void
{
    global $tests;
    $tests++;
    if (!$condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

stagingCheck(parseStagingAssetIDs('3,1') === [1,3], 'two asset IDs normalize and sort');
stagingCheck(parseStagingAssetIDs('9,3,6') === [3,6,9], 'three asset IDs normalize and sort');
stagingCheck(parseStagingAssetIDs('1,1,2') === [1,2], 'duplicate asset IDs are de-duplicated');

foreach (['1', '1,2,3,4', '1,nope', '0,2', '-1,2'] as $invalid) {
    $threw = false;
    try { parseStagingAssetIDs($invalid); } catch (InvalidArgumentException) { $threw = true; }
    stagingCheck($threw, "invalid staging asset set rejected: {$invalid}");
}

stagingCheck(isValidStagingEnvReference('CTVLMS_STAGE_KEY'), 'valid environment reference accepted');
stagingCheck(!isValidStagingEnvReference('bad-key'), 'invalid environment reference rejected');
stagingCheck(!isValidStagingEnvReference(''), 'empty environment reference rejected');

echo "PASS: {$tests} staging policy tests\n";
