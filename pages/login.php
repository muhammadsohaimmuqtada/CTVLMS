<?php
/**
 * CTVLMS — Login Page (standalone, no header/footer)
 */

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCSRF();
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($email === '' || $password === '') {
        $error = 'Please enter both email and password.';
    } elseif (login($email, $password)) {
        $uid = $_SESSION['user_id'];
        logAction('LOGIN', 'users', $uid, 'Logged in');
        redirect('?page=dashboard');
    } else {
        $error = 'Invalid email or password, or account is disabled.';
    }
}
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="CTVLMS — Login">
    <title>Login — <?= e(APP_NAME) ?></title>

    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

    <!-- Bootstrap 5.3 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">

    <!-- Custom Theme -->
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>

<div class="login-container">
    <div class="login-card glass-card text-center fade-in-up">
        <!-- Logo -->
        <div class="mb-4">
            <i class="bi bi-shield-lock-fill login-logo"></i>
            <h3 class="mt-3 fw-bold" style="letter-spacing:1px;">
                <span style="background:linear-gradient(135deg,var(--accent-cyan),var(--accent-blue));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">CTVLMS</span>
            </h3>
            <p class="text-muted small mb-0"><?= e(APP_FULL_NAME) ?></p>
        </div>

        <!-- Error Message -->
        <?php if ($error): ?>
            <div class="alert alert-danger d-flex align-items-center gap-2 text-start" role="alert">
                <i class="bi bi-exclamation-triangle-fill"></i>
                <span><?= e($error) ?></span>
            </div>
        <?php endif; ?>

        <!-- Login Form -->
        <form method="POST" action="?page=login" class="text-start">
            <?= csrfField() ?>

            <div class="mb-3">
                <label for="email" class="form-label">
                    <i class="bi bi-envelope"></i> Email Address
                </label>
                <input type="email"
                       class="form-control"
                       id="email"
                       name="email"
                       placeholder="analyst@ctvlms.local"
                       value="<?= e($_POST['email'] ?? '') ?>"
                       required
                       autofocus>
            </div>

            <div class="mb-4">
                <label for="password" class="form-label">
                    <i class="bi bi-key"></i> Password
                </label>
                <input type="password"
                       class="form-control"
                       id="password"
                       name="password"
                       placeholder="Enter your password"
                       required>
            </div>

            <button type="submit" class="btn btn-cyber w-100 py-2">
                <i class="bi bi-box-arrow-in-right me-1"></i> Sign In
            </button>
        </form>

        <div class="mt-4">
            <small class="text-muted">
                <i class="bi bi-shield-check"></i>
                Secure session · CSRF protected
            </small>
        </div>
    </div>
</div>

<!-- Bootstrap JS -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
