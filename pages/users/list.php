<?php
$pageTitle = 'User Management';
requireRole('Admin');
$db = getDB();

// Handle DELETE via POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    validateCSRF();
    if (!canWrite('users')) {
        flash('danger', 'Access denied.');
        redirect('?page=users/list');
    }
    $deleteId = (int)$_POST['delete_id'];
    // Prevent self-deletion
    $currentUser = getCurrentUser();
    if ($deleteId === (int)$currentUser['userID']) {
        flash('danger', 'You cannot delete your own account.');
        redirect('?page=users/list');
    }
    $stmt = $db->prepare('DELETE FROM users WHERE userID = :id');
    $stmt->execute([':id' => $deleteId]);
    logAction('DELETE', 'users', $deleteId, 'Deleted user');
    flash('success', 'User deleted successfully.');
    redirect('?page=users/list');
}

// Fetch all users
$stmt = $db->query('SELECT userID, fullName, email, role, isActive, createdAt FROM users ORDER BY createdAt DESC');
$rows = $stmt->fetchAll();

require __DIR__ . '/../../includes/header.php';
?>

<div class="page-header fade-in-up">
    <div>
        <h1 class="h3 mb-1"><i class="bi bi-people-fill me-2"></i><?= e($pageTitle) ?></h1>
        <p class="text-secondary mb-0">Manage system users and access roles</p>
    </div>
    <?php if (canWrite('users')): ?>
        <a href="?page=users/form" class="btn btn-cyber"><i class="bi bi-plus-lg me-1"></i>Add User</a>
    <?php endif; ?>
</div>

<div class="filter-bar fade-in-up">
    <div class="row g-3 align-items-end">
        <div class="col-md-6 col-lg-4">
            <label class="form-label text-secondary small">Search</label>
            <input type="text" class="form-control bg-dark text-light border-secondary" id="tableSearch" placeholder="Search users..." autocomplete="off">
        </div>
        <div class="col-auto ms-auto">
            <span class="badge bg-secondary"><?= count($rows) ?> user<?= count($rows) !== 1 ? 's' : '' ?></span>
        </div>
    </div>
</div>

<div class="glass-card p-0 fade-in-up">
    <div class="table-responsive">
        <table class="table table-dark-custom table-hover mb-0" id="dataTable">
            <thead>
                <tr>
                    <th>Full Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Created</th>
                    <?php if (canWrite('users')): ?><th class="text-end">Actions</th><?php endif; ?>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($rows)): ?>
                    <tr>
                        <td colspan="<?= canWrite('users') ? 6 : 5 ?>" class="text-center py-5">
                            <div class="empty-state">
                                <i class="bi bi-people display-4 text-secondary"></i>
                                <p class="text-secondary mt-2 mb-0">No users found</p>
                            </div>
                        </td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($rows as $row): ?>
                        <tr>
                            <td>
                                <i class="bi bi-person-circle me-1 text-secondary"></i>
                                <?= e($row['fullName']) ?>
                            </td>
                            <td class="font-mono"><?= e($row['email']) ?></td>
                            <td><?= roleLabel($row['role']) ?></td>
                            <td>
                                <?php if ($row['isActive']): ?>
                                    <span class="badge bg-success"><i class="bi bi-check-circle me-1"></i>Active</span>
                                <?php else: ?>
                                    <span class="badge bg-danger"><i class="bi bi-x-circle me-1"></i>Inactive</span>
                                <?php endif; ?>
                            </td>
                            <td class="text-secondary"><?= e(date('M j, Y', strtotime($row['createdAt']))) ?></td>
                            <?php if (canWrite('users')): ?>
                                <td class="text-end">
                                    <div class="btn-group btn-group-sm">
                                        <a href="?page=users/form&id=<?= (int)$row['userID'] ?>" class="btn btn-cyber-outline" title="Edit">
                                            <i class="bi bi-pencil"></i>
                                        </a>
                                        <form method="POST" action="?page=users/list" class="d-inline" onsubmit="return confirm('Delete user <?= e(addslashes($row['fullName'])) ?>?');">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="delete_id" value="<?= (int)$row['userID'] ?>">
                                            <button type="submit" class="btn btn-danger-cyber btn-sm" title="Delete">
                                                <i class="bi bi-trash"></i>
                                            </button>
                                        </form>
                                    </div>
                                </td>
                            <?php endif; ?>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
