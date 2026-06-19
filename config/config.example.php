<?php
/**
 * CTVLMS — Application Configuration (TEMPLATE)
 * 
 * Copy this file to config.php and fill in your values.
 *   cp config.example.php config.php
 */

define('DB_HOST', '127.0.0.1');
define('DB_PORT', 3306);
define('DB_NAME', 'ctvlms');
define('DB_USER', 'root');
define('DB_PASS', 'YOUR_PASSWORD_HERE');

define('APP_NAME', 'CTVLMS');
define('APP_FULL_NAME', 'Cyber Threat & Vulnerability Lifecycle Management System');
define('APP_URL', 'http://localhost:8000');

// Session hardening
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
ini_set('session.use_only_cookies', 1);
