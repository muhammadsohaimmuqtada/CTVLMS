<?php
/**
 * CTVLMS — Authentication & RBAC
 */

require_once __DIR__ . '/../config/database.php';

function startSecureSession(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

/**
 * Authenticate a user by email and password.
 * Returns true on success, false on failure.
 */
function login(string $email, string $password): bool
{
    $db   = getDB();
    $stmt = $db->prepare(
        'SELECT userID, fullName, email, passwordHash, role, isActive
         FROM users WHERE email = :email LIMIT 1'
    );
    $stmt->execute([':email' => $email]);
    $user = $stmt->fetch();

    if (!$user || !$user['isActive'] || !password_verify($password, $user['passwordHash'])) {
        return false;
    }

    // Prevent session fixation
    session_regenerate_id(true);

    $_SESSION['user_id']   = $user['userID'];
    $_SESSION['full_name'] = $user['fullName'];
    $_SESSION['email']     = $user['email'];
    $_SESSION['role']      = $user['role'];

    return true;
}

function logout(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
}

function isLoggedIn(): bool
{
    return isset($_SESSION['user_id']);
}

function requireLogin(): void
{
    if (!isLoggedIn()) {
        header('Location: ?page=login');
        exit;
    }
}

/**
 * Abort with 403 unless the current user has one of the given roles.
 */
function requireRole(string ...$roles): void
{
    requireLogin();
    if (!in_array($_SESSION['role'], $roles, true)) {
        http_response_code(403);
        include __DIR__ . '/header.php';
        echo '<div class="container py-5"><div class="alert alert-danger glass-card">';
        echo '<h4><i class="bi bi-shield-lock"></i> Access Denied</h4>';
        echo '<p>Your role (<strong>' . htmlspecialchars($_SESSION['role']) . '</strong>) does not have permission to view this page.</p>';
        echo '</div></div>';
        include __DIR__ . '/footer.php';
        exit;
    }
}

function getCurrentUser(): array
{
    return [
        'id'   => $_SESSION['user_id']   ?? null,
        'name' => $_SESSION['full_name'] ?? '',
        'email'=> $_SESSION['email']     ?? '',
        'role' => $_SESSION['role']      ?? '',
    ];
}

/**
 * Check if the current user can write (create/edit/delete) on a given entity.
 */
function canWrite(string $entity): bool
{
    $role = $_SESSION['role'] ?? '';
    $perms = [
        'users'           => ['Admin'],
        'assets'          => ['Admin', 'Vuln_Manager'],
        'vulnerabilities' => ['Admin', 'SOC_Analyst', 'Vuln_Manager'],
        'asset_vulns'     => ['Admin', 'SOC_Analyst', 'Vuln_Manager'],
        'threat_actors'   => ['Admin', 'SOC_Analyst', 'Red_Teamer'],
        'iocs'            => ['Admin', 'SOC_Analyst', 'Red_Teamer'],
        'incidents'       => ['Admin', 'SOC_Analyst'],
        'engagements'     => ['Admin', 'Red_Teamer'],
        'findings'        => ['Admin', 'Red_Teamer'],
        'remediations'    => ['Admin', 'SOC_Analyst', 'Vuln_Manager'],
        'audit_log'       => [],
    ];
    return in_array($role, $perms[$entity] ?? [], true);
}

/**
 * Check if a user can read a given entity page.
 * All authenticated users can read all entities.
 */
function canRead(string $entity): bool
{
    $role = $_SESSION['role'] ?? '';
    // Admin-only pages
    $adminOnly = ['users', 'audit_log'];
    if (in_array($entity, $adminOnly, true)) {
        return $role === 'Admin';
    }
    return isLoggedIn();
}
