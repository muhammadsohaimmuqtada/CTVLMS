<?php
require_once __DIR__ . '/../includes/scheduler.php';

$tests=0;
function schedulercheck(bool $ok,string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR,"FAIL: {$message}\n"); exit(1); }
}

putenv('CTVLMS_PACKAGE_ADVISORY_SYNC_HOURS');
schedulercheck(packageAdvisorySyncCadenceHours()===24,'package advisory cadence defaults to 24 hours');
putenv('CTVLMS_PACKAGE_ADVISORY_SYNC_HOURS=0');
schedulercheck(packageAdvisorySyncCadenceHours()===0,'zero package advisory cadence disables scheduled sync');
putenv('CTVLMS_PACKAGE_ADVISORY_SYNC_HOURS=9999');
schedulercheck(packageAdvisorySyncCadenceHours()===168,'package advisory cadence is bounded');
putenv('CTVLMS_PACKAGE_ADVISORY_SYNC_HOURS');

putenv('CTVLMS_TEST_TIMEOUT=1');
schedulercheck(boundedTimeoutFromEnv('CTVLMS_TEST_TIMEOUT',300,30,600)===30,'child timeout honors lower safety bound');
putenv('CTVLMS_TEST_TIMEOUT=9999');
schedulercheck(boundedTimeoutFromEnv('CTVLMS_TEST_TIMEOUT',300,30,600)===600,'child timeout honors upper safety bound');
putenv('CTVLMS_TEST_TIMEOUT');

schedulercheck(deriveCycleStatus([
    'nvd'=>['ok'=>true],'package_advisory_sync'=>['ok'=>true],
    'local_inventory'=>[],'ssh_inventory'=>[],'scans'=>[],'patches'=>[],
    'verification'=>['ok'=>true],'fatal_error'=>null,
])==='Succeeded','healthy cycle derives Succeeded');
schedulercheck(deriveCycleStatus([
    'nvd'=>['ok'=>true],'package_advisory_sync'=>['ok'=>true],
    'local_inventory'=>[['ok'=>false]],'ssh_inventory'=>[],'scans'=>[],'patches'=>[],
    'verification'=>['ok'=>true],'fatal_error'=>null,
])==='Partial','nonfatal child failure derives Partial');
schedulercheck(deriveCycleStatus([
    'nvd'=>['ok'=>true],'package_advisory_sync'=>['ok'=>true],
    'local_inventory'=>[],'ssh_inventory'=>[],'scans'=>[],'patches'=>[],
    'verification'=>['ok'=>true],'fatal_error'=>'database unavailable',
])==='Failed','fatal cycle error derives Failed');

echo "PASS: {$tests} scheduler policy tests\n";
