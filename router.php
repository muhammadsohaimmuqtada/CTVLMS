<?php
/**
 * Router for PHP's development server.
 * Only public/ static assets are served directly; repository internals, SQL,
 * configuration, tests, and Adminer are never exposed as static files.
 */
$path = rawurldecode((string)(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/'));
if (str_contains($path, "\0") || str_contains($path, '..')) {
    http_response_code(400);
    exit('Bad Request');
}
if ($path === '/healthz') {
    require_once __DIR__ . '/config/config.php';
    require_once __DIR__ . '/config/database.php';
    require_once __DIR__ . '/includes/health.php';
    emitCtvLmsHealth(getDB());
}
if (str_starts_with($path, '/public/')) {
    $file = __DIR__ . $path;
    if (is_file($file)) return false;
    http_response_code(404);
    exit('Not Found');
}
if ($path === '/favicon.ico') { http_response_code(204); exit; }
require __DIR__ . '/index.php';
