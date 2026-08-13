<?php
/** Production deployment validation and runtime safety checks. */

function ctvlmsProductionChecks(array $env): array
{
    $errors = [];
    $warnings = [];
    $mode = strtolower(trim((string)($env['CTVLMS_ENV'] ?? 'development')));
    $production = $mode === 'production';
    $appUrl = trim((string)($env['CTVLMS_APP_URL'] ?? ''));
    $dbUser = trim((string)($env['CTVLMS_DB_USER'] ?? ''));
    $dbPass = (string)($env['CTVLMS_DB_PASSWORD'] ?? '');
    $executePatches = (string)($env['CTVLMS_EXECUTE_PATCHES'] ?? '0');

    if (!in_array($mode, ['development','test','production'], true)) {
        $errors[] = 'CTVLMS_ENV must be development, test, or production.';
    }
    if ($appUrl === '' || filter_var($appUrl, FILTER_VALIDATE_URL) === false) {
        $errors[] = 'CTVLMS_APP_URL must be an absolute URL.';
    }
    if ($production && !str_starts_with(strtolower($appUrl), 'https://')) {
        $errors[] = 'Production requires an HTTPS CTVLMS_APP_URL.';
    }
    if ($dbUser === '') $errors[] = 'CTVLMS_DB_USER is required.';
    if ($production && strtolower($dbUser) === 'root') {
        $errors[] = 'Production application database user must not be root.';
    }
    if ($dbPass === '' || $dbPass === 'CHANGE_ME' || str_contains(strtolower($dbPass), 'replace-with')) {
        $errors[] = 'CTVLMS_DB_PASSWORD must be set to a non-placeholder secret.';
    }
    if (strlen($dbPass) < 16) {
        $production ? $errors[] = 'Production database password must be at least 16 characters.'
                    : $warnings[] = 'Database password is shorter than 16 characters.';
    }
    if (!in_array($executePatches, ['0','1'], true)) {
        $errors[] = 'CTVLMS_EXECUTE_PATCHES must be 0 or 1.';
    }
    if ($production && $executePatches === '1') {
        $warnings[] = 'Automatic patch execution is enabled; validate backup, rollout, SSH trust, and approval policy first.';
    }

    return [
        'mode'=>$mode,
        'ok'=>$errors === [],
        'errors'=>$errors,
        'warnings'=>$warnings,
    ];
}

function ctvlmsCurrentEnvironment(): array
{
    $keys = [
        'CTVLMS_ENV','CTVLMS_APP_URL','CTVLMS_DB_HOST','CTVLMS_DB_PORT','CTVLMS_DB_NAME',
        'CTVLMS_DB_USER','CTVLMS_DB_PASSWORD','CTVLMS_EXECUTE_PATCHES',
    ];
    $out = [];
    foreach ($keys as $key) {
        $value = getenv($key);
        if ($value !== false) $out[$key] = $value;
    }
    return $out;
}
