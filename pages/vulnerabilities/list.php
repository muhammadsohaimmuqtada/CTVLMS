<?php
$pageTitle = 'Vulnerabilities';
$db = getDB();

// Handle DELETE via POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    validateCSRF();
    if (!canWrite('vulnerabilities')) {
        flash('danger', 'Access denied.');
        redirect('?page=vulnerabilities/list');
    }
    $deleteId = (int)$_POST['delete_id'];
    $stmt = $db->prepare('DELETE FROM vulnerabilities WHERE vulnID = :id');
    $stmt->execute([':id' => $deleteId]);
    logAction('DELETE', 'vulnerabilities', $deleteId, 'Deleted vulnerability');
    flash('success', 'Vulnerability deleted successfully.');
    redirect('?page=vulnerabilities/list');
}

// Handle NIST Sync
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'sync_nist') {
    validateCSRF();
    if (!canWrite('vulnerabilities')) {
        flash('danger', 'Access denied.');
        redirect('?page=vulnerabilities/list');
    }
    require_once __DIR__ . '/../../includes/sync_cve.php';
    $added = syncNistCVEs($db);
    if ($added === false) {
        flash('danger', 'Failed to fetch data from NIST API. It might be rate-limited.');
    } else {
        flash('success', "Successfully synced {$added} new vulnerabilities from NIST NVD.");
    }
    redirect('?page=vulnerabilities/list');
}

// Build query with optional severity filter
$where = [];
$params = [];

$filterSeverity = $_GET['severity'] ?? '';
if ($filterSeverity !== '') {
    $where[] = 'severity = :sev';
    $params[':sev'] = $filterSeverity;
}

$sql = 'SELECT * FROM vulnerabilities';
if (!empty($where)) {
    $sql .= ' WHERE ' . implode(' AND ', $where);
}
$sql .= ' ORDER BY createdAt DESC';

$stmt = $db->prepare($sql);
$stmt->execute($params);
$rows = $stmt->fetchAll();

$severities = ['Low', 'Medium', 'High', 'Critical'];

require __DIR__ . '/../../includes/header.php';
?>

<div class="page-header fade-in-up">
    <div>
        <h1 class="h3 mb-1"><i class="bi bi-shield-exclamation me-2"></i><?= e($pageTitle) ?></h1>
        <p class="text-secondary mb-0">Vulnerability database and CVE tracking</p>
    </div>
    <?php if (canWrite('vulnerabilities')): ?>
        <div class="d-flex gap-2">
            <form method="POST" action="?page=vulnerabilities/list" class="m-0" onsubmit="this.querySelector('button').innerHTML = '<span class=\'spinner-border spinner-border-sm me-1\'></span> Syncing...';">
                <?= csrfField() ?>
                <input type="hidden" name="action" value="sync_nist">
                <button type="submit" class="btn btn-cyber-outline"><i class="bi bi-cloud-download me-1"></i>Sync NIST Data</button>
            </form>
            <a href="?page=vulnerabilities/form" class="btn btn-cyber"><i class="bi bi-plus-lg me-1"></i>Add Vulnerability</a>
        </div>
    <?php endif; ?>
</div>

<div class="filter-bar fade-in-up">
    <form method="GET" class="row g-3 align-items-end">
        <input type="hidden" name="page" value="vulnerabilities/list">
        <div class="col-md-4">
            <label class="form-label text-secondary small">Search</label>
            <input type="text" class="form-control bg-dark text-light border-secondary" id="tableSearch" placeholder="Search vulnerabilities..." autocomplete="off">
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
            <span class="badge bg-secondary"><?= count($rows) ?> vulnerabilit<?= count($rows) !== 1 ? 'ies' : 'y' ?></span>
        </div>
    </form>
</div>

<div class="glass-card p-0 fade-in-up">
    <div class="table-responsive">
        <table class="table table-dark-custom table-hover mb-0" id="dataTable">
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>Title</th>
                    <th>CVSS</th>
                    <th>Severity</th>
                    <th>CWE</th>
                    <th>Published</th>
                    <?php if (canWrite('vulnerabilities')): ?><th class="text-end">Actions</th><?php endif; ?>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($rows)): ?>
                    <tr>
                        <td colspan="<?= canWrite('vulnerabilities') ? 7 : 6 ?>" class="text-center py-5">
                            <div class="empty-state">
                                <i class="bi bi-shield-x display-4 text-secondary"></i>
                                <p class="text-secondary mt-2 mb-0">No vulnerabilities found</p>
                            </div>
                        </td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($rows as $row): ?>
                        <tr>
                            <td class="font-mono">
                                <?php if ($row['cveID']): ?>
                                    <span class="text-info"><?= e($row['cveID']) ?></span>
                                <?php else: ?>
                                    <span class="badge bg-secondary">Internal</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <strong><?= e($row['title']) ?></strong>
                            </td>
                            <td>
                                <?php
                                $score = (float)$row['cvssScore'];
                                $scoreClass = $score >= 9.0 ? 'text-danger' : ($score >= 7.0 ? 'text-warning' : ($score >= 4.0 ? 'text-info' : 'text-secondary'));
                                ?>
                                <span class="<?= $scoreClass ?> fw-bold"><?= e(number_format($score, 1)) ?></span>
                            </td>
                            <td><?= severityBadge($row['severity']) ?></td>
                            <td class="font-mono text-secondary"><?= e($row['cwe'] ?? '—') ?></td>
                            <td class="text-secondary"><?= $row['publishedDate'] ? e(date('M j, Y', strtotime($row['publishedDate']))) : '—' ?></td>
                            <?php if (canWrite('vulnerabilities')): ?>
                                <td class="text-end">
                                    <div class="btn-group btn-group-sm">
                                        <a href="?page=vulnerabilities/form&id=<?= (int)$row['vulnID'] ?>" class="btn btn-cyber-outline" title="Edit">
                                            <i class="bi bi-pencil"></i>
                                        </a>
                                        <form method="POST" action="?page=vulnerabilities/list" class="d-inline" onsubmit="return confirm('Delete this vulnerability?');">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="delete_id" value="<?= (int)$row['vulnID'] ?>">
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
