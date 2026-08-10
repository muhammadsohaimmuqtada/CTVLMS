<?php
/** CTVLMS configuration template. Copy to config/config.php. */
function ctvlmsEnv(string $name, string $default = ''): string
{
    $value = getenv($name);
    return $value === false || $value === '' ? $default : $value;
}

define('DB_HOST', ctvlmsEnv('CTVLMS_DB_HOST', '127.0.0.1'));
define('DB_PORT', (int)ctvlmsEnv('CTVLMS_DB_PORT', '3306'));
define('DB_NAME', ctvlmsEnv('CTVLMS_DB_NAME', 'ctvlms'));
define('DB_USER', ctvlmsEnv('CTVLMS_DB_USER', 'ctvlms_app'));
define('DB_PASS', ctvlmsEnv('CTVLMS_DB_PASSWORD', 'CHANGE_ME'));

define('APP_NAME', 'CTVLMS');
define('APP_FULL_NAME', 'Cyber Threat & Vulnerability Lifecycle Management System');
define('APP_URL', ctvlmsEnv('CTVLMS_APP_URL', 'http://127.0.0.1:8000'));

ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_secure', str_starts_with(APP_URL, 'https://') ? '1' : '0');
