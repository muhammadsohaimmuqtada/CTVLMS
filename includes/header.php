<?php
/**
 * CTVLMS — Shared Header (HTML head + navbar)
 *
 * Set $pageTitle before including this file.
 */

$pageTitle = $pageTitle ?? 'Dashboard';
$currentPage = $_GET['page'] ?? 'dashboard';
$user = getCurrentUser();

function navActive(string $prefix): string {
    global $currentPage;
    return str_starts_with($currentPage, $prefix) ? 'active' : '';
}
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="CTVLMS — Cyber Threat & Vulnerability Lifecycle Management System">
    <title><?= e($pageTitle) ?> — <?= e(APP_NAME) ?></title>

    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

    <!-- Bootstrap 5.3 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>

    <!-- Custom Theme -->
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>

<!-- Navbar -->
<nav class="navbar navbar-expand-xl navbar-dark sticky-top glass-nav">
    <div class="container-fluid">
        <a class="navbar-brand d-flex align-items-center gap-2" href="?page=dashboard">
            <i class="bi bi-shield-lock-fill brand-icon"></i>
            <span class="brand-text">CTVLMS</span>
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#mainNav">
            <span class="navbar-toggler-icon"></span>
        </button>

        <div class="collapse navbar-collapse" id="mainNav">
            <ul class="navbar-nav me-auto mb-2 mb-xl-0">
                <li class="nav-item">
                    <a class="nav-link <?= navActive('dashboard') ?>" href="?page=dashboard">
                        <i class="bi bi-speedometer2"></i> Dashboard
                    </a>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle <?= navActive('assets') || navActive('vulnerabilities') || navActive('asset_vulns') ? 'active' : '' ?>"
                       role="button" style="cursor: pointer;" data-bs-toggle="dropdown">
                        <i class="bi bi-hdd-rack"></i> Assets & Vulns
                    </a>
                    <ul class="dropdown-menu dropdown-menu-dark">
                        <li><a class="dropdown-item" href="?page=assets/list"><i class="bi bi-hdd-network"></i> Assets</a></li>
                        <li><a class="dropdown-item" href="?page=vulnerabilities/list"><i class="bi bi-bug"></i> Vulnerabilities</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item" href="?page=asset_vulns/list"><i class="bi bi-arrow-repeat"></i> Lifecycle Board</a></li>
                    </ul>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle <?= navActive('threat_actors') || navActive('iocs') || navActive('incidents') ? 'active' : '' ?>"
                       role="button" style="cursor: pointer;" data-bs-toggle="dropdown">
                        <i class="bi bi-shield-exclamation"></i> Threat Intel
                    </a>
                    <ul class="dropdown-menu dropdown-menu-dark">
                        <li><a class="dropdown-item" href="?page=threat_actors/list"><i class="bi bi-person-badge"></i> Threat Actors</a></li>
                        <li><a class="dropdown-item" href="?page=iocs/list"><i class="bi bi-fingerprint"></i> IOCs</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item" href="?page=incidents/list"><i class="bi bi-exclamation-triangle"></i> Incidents</a></li>
                    </ul>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle <?= navActive('engagements') || navActive('findings') || navActive('remediations') ? 'active' : '' ?>"
                       role="button" style="cursor: pointer;" data-bs-toggle="dropdown">
                        <i class="bi bi-crosshair"></i> Red Team
                    </a>
                    <ul class="dropdown-menu dropdown-menu-dark">
                        <li><a class="dropdown-item" href="?page=engagements/list"><i class="bi bi-calendar-check"></i> Engagements</a></li>
                        <li><a class="dropdown-item" href="?page=findings/list"><i class="bi bi-search"></i> Findings</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item" href="?page=remediations/list"><i class="bi bi-wrench"></i> Remediations</a></li>
                    </ul>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?= navActive('reports') ?>" href="?page=reports">
                        <i class="bi bi-file-earmark-bar-graph"></i> Reports
                    </a>
                </li>
                <?php if ($user['role'] === 'Admin'): ?>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle <?= navActive('users') || navActive('audit_log') ? 'active' : '' ?>"
                       role="button" style="cursor: pointer;" data-bs-toggle="dropdown">
                        <i class="bi bi-gear"></i> Admin
                    </a>
                    <ul class="dropdown-menu dropdown-menu-dark">
                        <li><a class="dropdown-item" href="?page=users/list"><i class="bi bi-people"></i> Users</a></li>
                        <li><a class="dropdown-item" href="?page=audit_log/list"><i class="bi bi-journal-text"></i> Audit Log</a></li>
                    </ul>
                </li>
                <?php endif; ?>
            </ul>

            <!-- User info -->
            <div class="d-flex align-items-center gap-3">
                <div class="user-info text-end d-none d-md-block">
                    <small class="text-muted d-block"><?= e($user['name']) ?></small>
                    <?= roleLabel($user['role']) ?>
                </div>
                <a href="?page=logout" class="btn btn-outline-danger btn-sm" title="Logout">
                    <i class="bi bi-box-arrow-right"></i>
                </a>
            </div>
        </div>
    </div>
</nav>

<!-- Flash Messages -->
<div class="container-fluid mt-3">
    <?= renderFlash() ?>
</div>

<!-- Main Content -->
<main class="container-fluid py-4">
