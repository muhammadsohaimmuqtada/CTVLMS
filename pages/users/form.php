<?php
$pageTitle = 'User';
requireRole('Admin');
$db = getDB();
$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$isEdit = $id > 0;
$entity = 'users';

if (!canWrite($entity)) {
    flash('danger', 'Access denied.');
    redirect("?page={$entity}/list");
}

// Load existing record for edit
$record = null;
if ($isEdit) {
    $stmt = $db->prepare('SELECT * FROM users WHERE userID = :id');
    $stmt->execute([':id' => $id]);
    $record = $stmt->fetch();
    if (!$record) {
        flash('danger', 'User not found.');
        redirect("?page={$entity}/list");
    }
    $pageTitle = 'Edit User';
} else {
    $pageTitle = 'Create User';
}

// Handle form submission
$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCSRF();

    $fullName   = trim($_POST['fullName'] ?? '');
    $email      = trim($_POST['email'] ?? '');
    $password   = $_POST['password'] ?? '';
    $role       = $_POST['role'] ?? '';
    $isActive   = isset($_POST['isActive']) ? 1 : 0;

    // Validation
    if ($fullName === '') $errors[] = 'Full name is required.';
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'A valid email is required.';
    if (!$isEdit && $password === '') $errors[] = 'Password is required for new users.';
    if ($password !== '' && strlen($password) < 8) $errors[] = 'Password must be at least 8 characters.';

    $validRoles = ['Admin', 'SOC_Analyst', 'Red_Teamer', 'Vuln_Manager', 'Viewer'];
    if (!in_array($role, $validRoles, true)) $errors[] = 'Invalid role selected.';

    // Check unique email
    if (empty($errors)) {
        $emailCheck = $db->prepare('SELECT userID FROM users WHERE email = :email' . ($isEdit ? ' AND userID != :id' : ''));
        $params = [':email' => $email];
        if ($isEdit) $params[':id'] = $id;
        $emailCheck->execute($params);
        if ($emailCheck->fetch()) $errors[] = 'Email address is already in use.';
    }

    if (empty($errors)) {
        if ($isEdit) {
            if ($password !== '') {
                $hash = password_hash($password, PASSWORD_BCRYPT);
                $stmt = $db->prepare('UPDATE users SET fullName = :fn, email = :em, passwordHash = :pw, role = :role, isActive = :ia WHERE userID = :id');
                $stmt->execute([':fn' => $fullName, ':em' => $email, ':pw' => $hash, ':role' => $role, ':ia' => $isActive, ':id' => $id]);
            } else {
                $stmt = $db->prepare('UPDATE users SET fullName = :fn, email = :em, role = :role, isActive = :ia WHERE userID = :id');
                $stmt->execute([':fn' => $fullName, ':em' => $email, ':role' => $role, ':ia' => $isActive, ':id' => $id]);
            }
            logAction('UPDATE', 'users', $id, "Updated user: {$fullName}");
            flash('success', 'User updated successfully.');
        } else {
            $hash = password_hash($password, PASSWORD_BCRYPT);
            $stmt = $db->prepare('INSERT INTO users (fullName, email, passwordHash, role, isActive) VALUES (:fn, :em, :pw, :role, :ia)');
            $stmt->execute([':fn' => $fullName, ':em' => $email, ':pw' => $hash, ':role' => $role, ':ia' => $isActive]);
            $newId = (int)$db->lastInsertId();
            logAction('CREATE', 'users', $newId, "Created user: {$fullName}");
            flash('success', 'User created successfully.');
        }
        redirect("?page={$entity}/list");
    }
}

require __DIR__ . '/../../includes/header.php';
?>

<div class="page-header fade-in-up">
    <div>
        <h1 class="h3 mb-1">
            <i class="bi bi-<?= $isEdit ? 'pencil-square' : 'person-plus-fill' ?> me-2"></i><?= e($pageTitle) ?>
        </h1>
        <p class="text-secondary mb-0"><?= $isEdit ? 'Modify user account details' : 'Add a new system user' ?></p>
    </div>
    <a href="?page=users/list" class="btn btn-cyber-outline"><i class="bi bi-arrow-left me-1"></i>Back to Users</a>
</div>

<?php if (!empty($errors)): ?>
    <div class="alert alert-danger fade-in-up">
        <i class="bi bi-exclamation-triangle-fill me-2"></i>
        <ul class="mb-0 ps-3">
            <?php foreach ($errors as $err): ?>
                <li><?= e($err) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<div class="glass-card fade-in-up">
    <form method="POST" action="?page=users/form<?= $isEdit ? '&id=' . $id : '' ?>">
        <?= csrfField() ?>

        <div class="row g-4">
            <div class="col-md-6">
                <label for="fullName" class="form-label">Full Name <span class="text-danger">*</span></label>
                <input type="text" class="form-control bg-dark text-light border-secondary" id="fullName" name="fullName"
                       value="<?= e($record['fullName'] ?? ($_POST['fullName'] ?? '')) ?>" required>
            </div>

            <div class="col-md-6">
                <label for="email" class="form-label">Email Address <span class="text-danger">*</span></label>
                <input type="email" class="form-control bg-dark text-light border-secondary" id="email" name="email"
                       value="<?= e($record['email'] ?? ($_POST['email'] ?? '')) ?>" required>
            </div>

            <div class="col-md-6">
                <label for="password" class="form-label">
                    Password <?= $isEdit ? '<span class="text-secondary small">(leave blank to keep current)</span>' : '<span class="text-danger">*</span>' ?>
                </label>
                <input type="password" class="form-control bg-dark text-light border-secondary" id="password" name="password"
                       minlength="8" <?= $isEdit ? '' : 'required' ?> autocomplete="new-password"
                       placeholder="<?= $isEdit ? '••••••••' : 'Min 8 characters' ?>">
            </div>

            <div class="col-md-6">
                <label for="role" class="form-label">Role <span class="text-danger">*</span></label>
                <select class="form-select bg-dark text-light border-secondary" id="role" name="role" required>
                    <option value="">— Select Role —</option>
                    <?php
                    $roles = ['Admin', 'SOC_Analyst', 'Red_Teamer', 'Vuln_Manager', 'Viewer'];
                    $currentRole = $record['role'] ?? ($_POST['role'] ?? '');
                    foreach ($roles as $r):
                    ?>
                        <option value="<?= e($r) ?>" <?= $currentRole === $r ? 'selected' : '' ?>><?= e(str_replace('_', ' ', $r)) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="col-md-6">
                <div class="form-check form-switch mt-4">
                    <?php
                    $isActiveChecked = $isEdit ? (bool)$record['isActive'] : (isset($_POST['isActive']) || $_SERVER['REQUEST_METHOD'] !== 'POST');
                    ?>
                    <input class="form-check-input" type="checkbox" id="isActive" name="isActive"
                           <?= $isActiveChecked ? 'checked' : '' ?>>
                    <label class="form-check-label" for="isActive">Account is Active</label>
                </div>
            </div>
        </div>

        <hr class="border-secondary my-4">

        <div class="d-flex gap-2">
            <button type="submit" class="btn btn-cyber">
                <i class="bi bi-check-lg me-1"></i><?= $isEdit ? 'Update User' : 'Create User' ?>
            </button>
            <a href="?page=users/list" class="btn btn-cyber-outline">Cancel</a>
        </div>
    </form>
</div>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
