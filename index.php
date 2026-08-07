<?php
/**
 * CTVLMS — Front Controller / Router
 *
 * Run: php -S localhost:8000
 * All requests hit this file; static files in public/ are served directly.
 */

// ---- Bootstrap application ----
require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/includes/audit.php';
require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/includes/lifecycle.php';

startSecureSession();

// ---- Determine requested page ----
$page = $_GET['page'] ?? 'dashboard';
$page = preg_replace('/[^a-zA-Z0-9_\/]/', '', $page); // sanitise

// ---- Handle logout ----
if ($page === 'logout') {
    logAction('LOGOUT', 'users', $_SESSION['user_id'] ?? null, 'User logged out');
    logout();
    redirect('?page=login');
}

// ---- Public routes (no auth required) ----
if ($page === 'login') {
    require __DIR__ . '/pages/login.php';
    exit;
}

// ---- All other routes require authentication ----
requireLogin();

// ---- Route map ----
$routes = [
    'dashboard'            => 'pages/dashboard.php',
    'reports'              => 'pages/reports.php',
    // Users (Admin only)
    'users/list'           => 'pages/users/list.php',
    'users/form'           => 'pages/users/form.php',
    // Assets
    'assets/list'          => 'pages/assets/list.php',
    'assets/form'          => 'pages/assets/form.php',
    // Vulnerabilities
    'vulnerabilities/list' => 'pages/vulnerabilities/list.php',
    'vulnerabilities/form' => 'pages/vulnerabilities/form.php',
    // Asset-Vulnerability Lifecycle
    'asset_vulns/list'     => 'pages/asset_vulns/list.php',
    'asset_vulns/form'     => 'pages/asset_vulns/form.php',
    // Threat Actors
    'threat_actors/list'   => 'pages/threat_actors/list.php',
    'threat_actors/form'   => 'pages/threat_actors/form.php',
    // IOCs
    'iocs/list'            => 'pages/iocs/list.php',
    'iocs/form'            => 'pages/iocs/form.php',
    // Incidents
    'incidents/list'       => 'pages/incidents/list.php',
    'incidents/form'       => 'pages/incidents/form.php',
    // Engagements
    'engagements/list'     => 'pages/engagements/list.php',
    'engagements/form'     => 'pages/engagements/form.php',
    // Findings
    'findings/list'        => 'pages/findings/list.php',
    'findings/form'        => 'pages/findings/form.php',
    // Remediations
    'remediations/list'    => 'pages/remediations/list.php',
    'remediations/form'    => 'pages/remediations/form.php',
    // Audit Log (Admin only)
    'audit_log/list'       => 'pages/audit_log/list.php',
];

if (!isset($routes[$page])) {
    http_response_code(404);
    $pageTitle = '404 Not Found';
    require __DIR__ . '/includes/header.php';
    echo '<div class="container py-5 text-center">
            <div class="glass-card p-5 mx-auto" style="max-width:500px;">
              <i class="bi bi-exclamation-triangle" style="font-size:4rem;color:var(--accent-orange);"></i>
              <h3 class="mt-3">Page Not Found</h3>
              <p class="text-muted">The page you\'re looking for doesn\'t exist.</p>
              <a href="?page=dashboard" class="btn btn-cyber mt-2">Back to Dashboard</a>
            </div>
          </div>';
    require __DIR__ . '/includes/footer.php';
    exit;
}

require __DIR__ . '/' . $routes[$page];
