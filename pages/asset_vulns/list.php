<?php
$pageTitle = 'Vulnerability Lifecycle Board';
$db = getDB();

// Handle DELETE via POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    validateCSRF();
    if (!canWrite('asset_vulns')) {
        flash('danger', 'Access denied.');
        redirect('?page=asset_vulns/list');
    }
    $deleteId = (int)$_POST['delete_id'];
    $stmt = $db->prepare('DELETE FROM asset_vulnerabilities WHERE assetVulnID = :id');
    $stmt->execute([':id' => $deleteId]);
    logAction('DELETE', 'asset_vulnerabilities', $deleteId, 'Deleted asset-vulnerability mapping');
    flash('success', 'Record deleted successfully.');
    redirect('?page=asset_vulns/list');
}

// Build query with optional filters
$where = [];
$params = [];

$filterStatus   = $_GET['status'] ?? '';
$filterSeverity = $_GET['severity'] ?? '';

if ($filterStatus !== '') {
    $where[] = 'av.status = :status';
    $params[':status'] = $filterStatus;
}
if ($filterSeverity !== '') {
    $where[] = 'v.severity = :sev';
    $params[':sev'] = $filterSeverity;
}

$sql = 'SELECT av.*, a.assetName, v.cveID, v.title AS vulnTitle, v.severity,
               u.fullName AS triagedByName
        FROM asset_vulnerabilities av
        JOIN assets a ON av.assetID = a.assetID
        JOIN vulnerabilities v ON av.vulnID = v.vulnID
        LEFT JOIN users u ON av.triagedByUserID = u.userID';
if (!empty($where)) {
    $sql .= ' WHERE ' . implode(' AND ', $where);
}
$sql .= ' ORDER BY av.discoveredDate DESC, av.assetVulnID DESC';

$stmt = $db->prepare($sql);
$stmt->execute($params);
$rows = $stmt->fetchAll();

$statuses = ['Discovered', 'Triaged', 'Confirmed', 'Remediation_In_Progress', 'Remediated', 'Verified_Closed', 'Risk_Accepted'];
$severities = ['Low', 'Medium', 'High', 'Critical'];

$csrfToken = generateCSRFToken();

require __DIR__ . '/../../includes/header.php';
?>

<div class="page-header fade-in-up">
    <div>
        <h1 class="h3 mb-1"><i class="bi bi-kanban-fill me-2"></i><?= e($pageTitle) ?></h1>
        <p class="text-secondary mb-0">Track vulnerability status across all assets — the heart of your lifecycle management</p>
    </div>
    <?php if (canWrite('asset_vulns')): ?>
        <a href="?page=asset_vulns/form" class="btn btn-cyber"><i class="bi bi-plus-lg me-1"></i>Map Vulnerability</a>
    <?php endif; ?>
</div>

<div class="filter-bar fade-in-up">
    <form method="GET" class="row g-3 align-items-end">
        <input type="hidden" name="page" value="asset_vulns/list">
        <div class="col-md-3">
            <label class="form-label text-secondary small">Search</label>
            <input type="text" class="form-control bg-dark text-light border-secondary" id="tableSearch" placeholder="Search records..." autocomplete="off">
        </div>
        <div class="col-md-3">
            <label class="form-label text-secondary small">Status</label>
            <select class="form-select bg-dark text-light border-secondary" name="status" onchange="this.form.submit()">
                <option value="">All Statuses</option>
                <?php foreach ($statuses as $st): ?>
                    <option value="<?= e($st) ?>" <?= $filterStatus === $st ? 'selected' : '' ?>><?= e(str_replace('_', ' ', $st)) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-md-3">
            <label class="form-label text-secondary small">Severity</label>
            <select class="form-select bg-dark text-light border-secondary" name="severity" onchange="this.form.submit()">
                <option value="">All Severities</option>
                <?php foreach ($severities as $s): ?>
                    <option value="<?= e($s) ?>" <?= $filterSeverity === $s ? 'selected' : '' ?>><?= e($s) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-auto ms-auto">
            <span class="badge bg-secondary"><?= count($rows) ?> record<?= count($rows) !== 1 ? 's' : '' ?></span>
        </div>
    </form>
</div>

<div class="glass-card p-0 fade-in-up">
    <div class="table-responsive">
        <table class="table table-dark-custom table-hover mb-0" id="dataTable">
            <thead>
                <tr>
                    <th>Asset</th>
                    <th>CVE ID</th>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Discovered</th>
                    <th>Triaged By</th>
                    <th>Due Date</th>
                    <th>Closed</th>
                    <?php if (canWrite('asset_vulns')): ?><th class="text-end">Actions</th><?php endif; ?>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($rows)): ?>
                    <tr>
                        <td colspan="<?= canWrite('asset_vulns') ? 10 : 9 ?>" class="text-center py-5">
                            <div class="empty-state">
                                <i class="bi bi-kanban display-4 text-secondary"></i>
                                <p class="text-secondary mt-2 mb-0">No asset-vulnerability mappings found</p>
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
                            <td class="font-mono">
                                <?php if ($row['cveID']): ?>
                                    <span class="text-info"><?= e($row['cveID']) ?></span>
                                <?php else: ?>
                                    <span class="badge bg-secondary">Internal</span>
                                <?php endif; ?>
                            </td>
                            <td><?= e($row['vulnTitle']) ?></td>
                            <td><?= severityBadge($row['severity']) ?></td>
                            <td>
                                <?php if (canWrite('asset_vulns')): ?>
                                    <select class="form-select form-select-sm bg-dark text-light border-secondary status-select"
                                            data-id="<?= (int)$row['assetVulnID'] ?>"
                                            data-page="asset_vulns"
                                            data-csrf="<?= e($csrfToken) ?>"
                                            style="min-width: 170px;">
                                        <?php foreach ($statuses as $st): ?>
                                            <option value="<?= e($st) ?>" <?= $row['status'] === $st ? 'selected' : '' ?>><?= e(str_replace('_', ' ', $st)) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                <?php else: ?>
                                    <?= statusBadge($row['status']) ?>
                                <?php endif; ?>
                            </td>
                            <td class="text-secondary"><?= $row['discoveredDate'] ? e(date('M j, Y', strtotime($row['discoveredDate']))) : '—' ?></td>
                            <td><?= e($row['triagedByName'] ?? '—') ?></td>
                            <td>
                                <?php if ($row['dueDate']): ?>
                                    <?php
                                    $due = strtotime($row['dueDate']);
                                    $overdue = $due < time() && !in_array($row['status'], ['Remediated', 'Verified_Closed', 'Risk_Accepted']);
                                    ?>
                                    <span class="<?= $overdue ? 'text-danger fw-bold' : 'text-secondary' ?>">
                                        <?= e(date('M j, Y', $due)) ?>
                                        <?php if ($overdue): ?><i class="bi bi-exclamation-triangle-fill ms-1"></i><?php endif; ?>
                                    </span>
                                <?php else: ?>
                                    —
                                <?php endif; ?>
                            </td>
                            <td class="text-secondary"><?= $row['closedDate'] ? e(date('M j, Y', strtotime($row['closedDate']))) : '—' ?></td>
                            <?php if (canWrite('asset_vulns')): ?>
                                <td class="text-end">
                                    <div class="btn-group btn-group-sm">
                                        <a href="?page=asset_vulns/form&id=<?= (int)$row['assetVulnID'] ?>" class="btn btn-cyber-outline" title="Edit">
                                            <i class="bi bi-pencil"></i>
                                        </a>
                                        <form method="POST" action="?page=asset_vulns/list" class="d-inline" onsubmit="return confirm('Delete this mapping?');">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="delete_id" value="<?= (int)$row['assetVulnID'] ?>">
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
