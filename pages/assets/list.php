<?php
$pageTitle = 'Asset Inventory';
$db = getDB();

// Handle DELETE via POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    validateCSRF();
    if (!canWrite('assets')) {
        flash('danger', 'Access denied.');
        redirect('?page=assets/list');
    }
    $deleteId = (int)$_POST['delete_id'];
    $stmt = $db->prepare('DELETE FROM assets WHERE assetID = :id');
    $stmt->execute([':id' => $deleteId]);
    logAction('DELETE', 'assets', $deleteId, 'Deleted asset');
    flash('success', 'Asset deleted successfully.');
    redirect('?page=assets/list');
}

// Build query with optional filters
$where = [];
$params = [];

$filterType = $_GET['assetType'] ?? '';
$filterCrit = $_GET['criticality'] ?? '';

if ($filterType !== '') {
    $where[] = 'a.assetType = :atype';
    $params[':atype'] = $filterType;
}
if ($filterCrit !== '') {
    $where[] = 'a.criticality = :crit';
    $params[':crit'] = $filterCrit;
}

$sql = 'SELECT a.*, u.fullName AS ownerName
        FROM assets a
        LEFT JOIN users u ON a.ownerUserID = u.userID';
if (!empty($where)) {
    $sql .= ' WHERE ' . implode(' AND ', $where);
}
$sql .= ' ORDER BY a.createdAt DESC';

$stmt = $db->prepare($sql);
$stmt->execute($params);
$rows = $stmt->fetchAll();

$assetTypes = ['Server', 'Workstation', 'Network_Device', 'Web_App', 'Database', 'Cloud_Resource', 'IoT_Device'];
$criticalities = ['Low', 'Medium', 'High', 'Critical'];

require __DIR__ . '/../../includes/header.php';
?>

<div class="page-header fade-in-up">
    <div>
        <h1 class="h3 mb-1"><i class="bi bi-hdd-rack-fill me-2"></i><?= e($pageTitle) ?></h1>
        <p class="text-secondary mb-0">Track and manage organizational assets</p>
    </div>
    <?php if (canWrite('assets')): ?>
        <a href="?page=assets/form" class="btn btn-cyber"><i class="bi bi-plus-lg me-1"></i>Add Asset</a>
    <?php endif; ?>
</div>

<div class="filter-bar fade-in-up">
    <form method="GET" class="row g-3 align-items-end">
        <input type="hidden" name="page" value="assets/list">
        <div class="col-md-3">
            <label class="form-label text-secondary small">Search</label>
            <input type="text" class="form-control bg-dark text-light border-secondary" id="tableSearch" placeholder="Search assets..." autocomplete="off">
        </div>
        <div class="col-md-3">
            <label class="form-label text-secondary small">Asset Type</label>
            <select class="form-select bg-dark text-light border-secondary" name="assetType" onchange="this.form.submit()">
                <option value="">All Types</option>
                <?php foreach ($assetTypes as $t): ?>
                    <option value="<?= e($t) ?>" <?= $filterType === $t ? 'selected' : '' ?>><?= e(str_replace('_', ' ', $t)) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-md-3">
            <label class="form-label text-secondary small">Criticality</label>
            <select class="form-select bg-dark text-light border-secondary" name="criticality" onchange="this.form.submit()">
                <option value="">All Levels</option>
                <?php foreach ($criticalities as $c): ?>
                    <option value="<?= e($c) ?>" <?= $filterCrit === $c ? 'selected' : '' ?>><?= e($c) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-auto ms-auto">
            <span class="badge bg-secondary"><?= count($rows) ?> asset<?= count($rows) !== 1 ? 's' : '' ?></span>
        </div>
    </form>
</div>

<div class="glass-card p-0 fade-in-up">
    <div class="table-responsive">
        <table class="table table-dark-custom table-hover mb-0" id="dataTable">
            <thead>
                <tr>
                    <th>Asset Name</th>
                    <th>Type</th>
                    <th>IP Address</th>
                    <th>OS / Platform</th>
                    <th>Owner</th>
                    <th>Criticality</th>
                    <th>Environment</th>
                    <th>Created</th>
                    <?php if (canWrite('assets')): ?><th class="text-end">Actions</th><?php endif; ?>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($rows)): ?>
                    <tr>
                        <td colspan="<?= canWrite('assets') ? 9 : 8 ?>" class="text-center py-5">
                            <div class="empty-state">
                                <i class="bi bi-hdd-rack display-4 text-secondary"></i>
                                <p class="text-secondary mt-2 mb-0">No assets found</p>
                            </div>
                        </td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($rows as $row): ?>
                        <tr>
                            <td>
                                <i class="bi bi-hdd-network me-1 text-secondary"></i>
                                <strong><?= e($row['assetName']) ?></strong>
                            </td>
                            <td><span class="badge bg-secondary"><?= e(str_replace('_', ' ', $row['assetType'])) ?></span></td>
                            <td class="font-mono"><?= e($row['ipAddress'] ?? '—') ?></td>
                            <td><?= e($row['osPlatform'] ?? '—') ?></td>
                            <td><?= e($row['ownerName'] ?? '—') ?></td>
                            <td><?= criticalityBadge($row['criticality']) ?></td>
                            <td><span class="badge bg-secondary"><?= e($row['environment'] ?? '—') ?></span></td>
                            <td class="text-secondary"><?= e(date('M j, Y', strtotime($row['createdAt']))) ?></td>
                            <?php if (canWrite('assets')): ?>
                                <td class="text-end">
                                    <div class="btn-group btn-group-sm">
                                        <a href="?page=assets/form&id=<?= (int)$row['assetID'] ?>" class="btn btn-cyber-outline" title="Edit">
                                            <i class="bi bi-pencil"></i>
                                        </a>
                                        <form method="POST" action="?page=assets/list" class="d-inline" onsubmit="return confirm('Delete asset <?= e(addslashes($row['assetName'])) ?>?');">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="delete_id" value="<?= (int)$row['assetID'] ?>">
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
