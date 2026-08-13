<?php
require_once __DIR__ . '/../includes/production.php';

$tests = 0;
function prodcheck(bool $ok, string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

$good = ctvlmsProductionChecks([
    'CTVLMS_ENV'=>'production',
    'CTVLMS_APP_URL'=>'https://ctvlms.example.com',
    'CTVLMS_DB_USER'=>'ctvlms_app',
    'CTVLMS_DB_PASSWORD'=>'this-is-a-long-random-password',
    'CTVLMS_EXECUTE_PATCHES'=>'0',
]);
prodcheck($good['ok'] === true, 'valid production configuration passes');

$http = ctvlmsProductionChecks([
    'CTVLMS_ENV'=>'production',
    'CTVLMS_APP_URL'=>'http://ctvlms.example.com',
    'CTVLMS_DB_USER'=>'ctvlms_app',
    'CTVLMS_DB_PASSWORD'=>'this-is-a-long-random-password',
    'CTVLMS_EXECUTE_PATCHES'=>'0',
]);
prodcheck($http['ok'] === false, 'production rejects HTTP application URL');

$root = ctvlmsProductionChecks([
    'CTVLMS_ENV'=>'production',
    'CTVLMS_APP_URL'=>'https://ctvlms.example.com',
    'CTVLMS_DB_USER'=>'root',
    'CTVLMS_DB_PASSWORD'=>'this-is-a-long-random-password',
    'CTVLMS_EXECUTE_PATCHES'=>'0',
]);
prodcheck($root['ok'] === false, 'production rejects root application DB user');

$placeholder = ctvlmsProductionChecks([
    'CTVLMS_ENV'=>'production',
    'CTVLMS_APP_URL'=>'https://ctvlms.example.com',
    'CTVLMS_DB_USER'=>'ctvlms_app',
    'CTVLMS_DB_PASSWORD'=>'CHANGE_ME',
    'CTVLMS_EXECUTE_PATCHES'=>'0',
]);
prodcheck($placeholder['ok'] === false, 'placeholder database password is rejected');

$patches = ctvlmsProductionChecks([
    'CTVLMS_ENV'=>'production',
    'CTVLMS_APP_URL'=>'https://ctvlms.example.com',
    'CTVLMS_DB_USER'=>'ctvlms_app',
    'CTVLMS_DB_PASSWORD'=>'this-is-a-long-random-password',
    'CTVLMS_EXECUTE_PATCHES'=>'1',
]);
prodcheck($patches['ok'] === true && count($patches['warnings']) === 1, 'auto patching is an explicit production warning, not silent');

echo "PASS: {$tests} production configuration tests\n";
