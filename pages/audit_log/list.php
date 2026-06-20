<?php
/**
 * CTVLMS — Audit Log (Admin Only, Read-Only)
 */

$pageTitle = 'Audit Log';
requireRole('Admin');

$db = getDB();

// ── Filters ──────────────────────────────────────────────────────────

$filterType  = $_GET['type'] ?? '';
$filterSearch = trim($_GET['q'] ?? '');
$page        = max(1, (int)($_GET['pg'] ?? 1));
$perPage     = 25;

$actionTypes = [
    'CREATE', 'UPDATE', 'DELETE', 'STATUS_CHANGE',
    'LOGIN', 'LOGOUT', 'SYSTEM_INIT',
];

// ── Build Query ──────────────────────────────────────────────────────

$where  = '';
$params = [];

if ($filterType !== '' && in_array($filterType, $actionTypes, true)) {
    $where .= ' AND al.actionType = :atype';
    $params[':atype'] = $filterType;
}

if ($filterSearch !== '') {
    $where .= ' AND (al.tableAffected LIKE :q OR al.actionDetail LIKE :q2 OR u.fullName LIKE :q3)';
    $params[':q']  = '%' . $filterSearch . '%';
    $params[':q2'] = '%' . $filterSearch . '%';
    $params[':q3'] = '%' . $filterSearch . '%';
}

$countSql = "SELECT COUNT(*)
             FROM audit_log al
             LEFT JOIN users u ON al.userID = u.userID
             WHERE 1=1 {$where}";

$dataSql  = "SELECT al.logID, al.userID, u.fullName, al.actionType,
                    al.tableAffected, al.recordID, al.actionDetail,
                    al.actionTimestamp
             FROM audit_log al
             LEFT JOIN users u ON al.userID = u.userID
             WHERE 1=1 {$where}
             ORDER BY al.actionTimestamp DESC";

$result = paginate($db, $countSql, $dataSql, $params, $page, $perPage);

// ── Build current filter URL for pagination links ────────────────────

$baseUrl = '?page=audit_log/list';
if ($filterType !== '')  $baseUrl .= '&type=' . urlencode($filterType);
if ($filterSearch !== '') $baseUrl .= '&q=' . urlencode($filterSearch);

require __DIR__ . '/../../includes/header.php';
?>

<div class="page-header">
    <h2><i class="bi bi-journal-text"></i> Audit Log</h2>
    <span class="text-muted small"><?= e((string)$result['total']) ?> total entries</span>
</div>

<!-- ── Filter Bar ─────────────────────────────────────────────────── -->
<form method="GET" class="filter-bar">
    <input type="hidden" name="page" value="audit_log/list">

    <select name="type" class="form-select" style="max-width:200px;" onchange="this.form.submit()">
        <option value="">All Action Types</option>
        <?php foreach ($actionTypes as $at): ?>
            <option value="<?= e($at) ?>" <?= $filterType === $at ? 'selected' : '' ?>>
                <?= e($at) ?>
            </option>
        <?php endforeach; ?>
    </select>

    <input type="text"
           name="q"
           id="tableSearch"
           class="form-control"
           placeholder="Search table, detail, user..."
           style="max-width:260px;"
           value="<?= e($filterSearch) ?>">

    <button type="submit" class="btn btn-cyber-outline btn-sm">
        <i class="bi bi-funnel"></i> Filter
    </button>

    <?php if ($filterType !== '' || $filterSearch !== ''): ?>
        <a href="?page=audit_log/list" class="btn btn-outline-secondary btn-sm">
            <i class="bi bi-x-lg"></i> Clear
        </a>
    <?php endif; ?>
</form>

<!-- ── Audit Table ────────────────────────────────────────────────── -->
<div class="glass-card p-0">
    <div class="table-responsive">
        <table class="table table-dark-custom table-hover mb-0">
            <thead>
                <tr>
                    <th>#</th>
                    <th>User</th>
                    <th>Action</th>
                    <th>Table</th>
                    <th>Record ID</th>
                    <th>Detail</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($result['rows'])): ?>
                    <tr>
                        <td colspan="7">
                            <div class="empty-state">
                                <i class="bi bi-journal-x d-block"></i>
                                <p>No audit log entries found.</p>
                            </div>
                        </td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($result['rows'] as $row): ?>
                        <?php
                        // Badge color for action type
                        $typeBadge = match ($row['actionType']) {
                            'CREATE'        => 'badge-low',
                            'UPDATE'        => 'bg-info',
                            'DELETE'        => 'badge-critical',
                            'STATUS_CHANGE' => 'bg-warning text-dark',
                            'LOGIN'         => 'bg-primary',
                            'LOGOUT'        => 'bg-secondary',
                            'SYSTEM_INIT'   => 'bg-purple',
                            default         => 'bg-secondary',
                        };

                        // Truncate detail
                        $detail = $row['actionDetail'] ?? '';
                        $truncated = strlen($detail) > 80
                            ? substr($detail, 0, 80) . '…'
                            : $detail;
                        ?>
                        <tr>
                            <td class="text-muted"><?= e((string)$row['logID']) ?></td>
                            <td><?= e($row['fullName'] ?? 'System') ?></td>
                            <td><span class="badge <?= $typeBadge ?>"><?= e($row['actionType']) ?></span></td>
                            <td><span class="font-mono"><?= e($row['tableAffected'] ?? '') ?></span></td>
                            <td class="font-mono"><?= e((string)($row['recordID'] ?? '—')) ?></td>
                            <td title="<?= e($detail) ?>"><?= e($truncated) ?></td>
                            <td class="text-muted text-nowrap"><?= e($row['actionTimestamp'] ?? '') ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- ── Pagination ─────────────────────────────────────────────────── -->
<div class="mt-3">
    <?= paginationLinks($result['current'], $result['pages'], $baseUrl) ?>
</div>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
