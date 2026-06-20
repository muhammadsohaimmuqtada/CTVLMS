<?php
/**
 * CTVLMS — Engagements List
 */

$pageTitle = 'Engagements';
$db = getDB();
$entity = 'engagements';

// ---- Handle DELETE via POST ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    validateCSRF();
    if (!canWrite($entity)) {
        flash('danger', 'Access denied.');
        redirect('?page=engagements/list');
    }
    $delId = (int)$_POST['delete_id'];

    // Delete associated engagement_assets first
    $stmt = $db->prepare('DELETE FROM engagement_assets WHERE engagementID = :id');
    $stmt->execute([':id' => $delId]);

    $stmt = $db->prepare('DELETE FROM engagements WHERE engagementID = :id');
    $stmt->execute([':id' => $delId]);
    logAction('DELETE', 'engagements', $delId, 'Deleted engagement');
    flash('success', 'Engagement deleted successfully.');
    redirect('?page=engagements/list');
}

// ---- Filters ----
$filterStatus = $_GET['status'] ?? '';
$filterType   = $_GET['type']   ?? '';
$page         = max(1, (int)($_GET['pg'] ?? 1));

$where  = [];
$params = [];

if ($filterStatus !== '') {
    $where[]              = 'e.status = :status';
    $params[':status']    = $filterStatus;
}
if ($filterType !== '') {
    $where[]            = 'e.engagementType = :etype';
    $params[':etype']   = $filterType;
}

$whereSQL = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$countSql = "SELECT COUNT(*) FROM engagements e {$whereSQL}";

$dataSql = "SELECT e.*, u.fullName AS leadName
            FROM engagements e
            LEFT JOIN users u ON e.leadUserID = u.userID
            {$whereSQL}
            ORDER BY e.startDate DESC, e.engagementID DESC";

$result       = paginate($db, $countSql, $dataSql, $params, $page, 15);
$rows         = $result['rows'];
$totalPages   = $result['pages'];
$currentPage  = $result['current'];

// Build base URL for pagination
$baseUrl = '?page=engagements/list';
if ($filterStatus !== '') $baseUrl .= '&status=' . urlencode($filterStatus);
if ($filterType !== '')   $baseUrl .= '&type='   . urlencode($filterType);

$statuses = ['Planned', 'In_Progress', 'Completed', 'Cancelled'];
$types    = ['Pentest', 'Red_Team', 'Purple_Team', 'Vuln_Assessment'];

require __DIR__ . '/../../includes/header.php';
?>

<!-- Page Header -->
<div class="page-header">
    <div>
        <h1 class="h3 mb-0"><i class="bi bi-calendar-check me-2"></i><?= e($pageTitle) ?></h1>
        <small class="text-muted"><?= $result['total'] ?> engagement<?= $result['total'] !== 1 ? 's' : '' ?> found</small>
    </div>
    <?php if (canWrite($entity)): ?>
    <a href="?page=engagements/form" class="btn btn-cyber">
        <i class="bi bi-plus-lg me-1"></i> New Engagement
    </a>
    <?php endif; ?>
</div>

<!-- Filters -->
<div class="filter-bar glass-card p-3 mb-4">
    <form method="GET" class="row g-2 align-items-end">
        <input type="hidden" name="page" value="engagements/list">
        <div class="col-md-3">
            <label class="form-label small text-muted">Status</label>
            <select name="status" class="form-select form-select-sm">
                <option value="">All Statuses</option>
                <?php foreach ($statuses as $s): ?>
                <option value="<?= e($s) ?>" <?= $filterStatus === $s ? 'selected' : '' ?>>
                    <?= e(str_replace('_', ' ', $s)) ?>
                </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-md-3">
            <label class="form-label small text-muted">Type</label>
            <select name="type" class="form-select form-select-sm">
                <option value="">All Types</option>
                <?php foreach ($types as $t): ?>
                <option value="<?= e($t) ?>" <?= $filterType === $t ? 'selected' : '' ?>>
                    <?= e(str_replace('_', ' ', $t)) ?>
                </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-md-3">
            <label class="form-label small text-muted">Search</label>
            <input type="text" id="tableSearch" class="form-control form-control-sm"
                   placeholder="Quick filter…">
        </div>
        <div class="col-md-3 d-flex gap-2">
            <button type="submit" class="btn btn-cyber-outline btn-sm flex-fill">
                <i class="bi bi-funnel me-1"></i> Filter
            </button>
            <a href="?page=engagements/list" class="btn btn-outline-secondary btn-sm flex-fill">
                <i class="bi bi-x-lg me-1"></i> Clear
            </a>
        </div>
    </form>
</div>

<!-- Data Table -->
<div class="glass-card p-0 fade-in-up">
    <div class="table-responsive">
        <table class="table table-dark-custom table-hover mb-0">
            <thead>
                <tr>
                    <th>Engagement Name</th>
                    <th>Type</th>
                    <th>Lead</th>
                    <th>Start Date</th>
                    <th>End Date</th>
                    <th>Status</th>
                    <th>Scope Summary</th>
                    <?php if (canWrite($entity)): ?>
                    <th class="text-end">Actions</th>
                    <?php endif; ?>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($rows)): ?>
                <tr>
                    <td colspan="<?= canWrite($entity) ? 8 : 7 ?>" class="text-center py-5">
                        <div class="empty-state">
                            <i class="bi bi-calendar-x" style="font-size:2.5rem;color:var(--accent-cyan);"></i>
                            <p class="mt-2 mb-0 text-muted">No engagements found.</p>
                        </div>
                    </td>
                </tr>
                <?php else: ?>
                <?php foreach ($rows as $row): ?>
                <tr>
                    <td>
                        <strong><?= e($row['engagementName']) ?></strong>
                    </td>
                    <td>
                        <?php
                        $typeColors = [
                            'Pentest'         => 'bg-info',
                            'Red_Team'        => 'bg-danger',
                            'Purple_Team'     => 'bg-purple',
                            'Vuln_Assessment' => 'bg-warning text-dark',
                        ];
                        $cls = $typeColors[$row['engagementType']] ?? 'bg-secondary';
                        ?>
                        <span class="badge <?= $cls ?>"><?= e(str_replace('_', ' ', $row['engagementType'])) ?></span>
                    </td>
                    <td><?= e($row['leadName'] ?? '—') ?></td>
                    <td class="font-mono"><?= e($row['startDate'] ?? '—') ?></td>
                    <td class="font-mono"><?= e($row['endDate'] ?? '—') ?></td>
                    <td><?= statusBadge($row['status']) ?></td>
                    <td>
                        <?php
                        $scope = $row['scopeSummary'] ?? '';
                        echo e(strlen($scope) > 80 ? substr($scope, 0, 80) . '…' : $scope);
                        ?>
                    </td>
                    <?php if (canWrite($entity)): ?>
                    <td class="text-end text-nowrap">
                        <a href="?page=engagements/form&id=<?= (int)$row['engagementID'] ?>"
                           class="btn btn-cyber-outline btn-sm" title="Edit">
                            <i class="bi bi-pencil"></i>
                        </a>
                        <form method="POST" action="?page=engagements/list" class="d-inline">
                            <?= csrfField() ?>
                            <input type="hidden" name="delete_id" value="<?= (int)$row['engagementID'] ?>">
                            <button type="submit" class="btn btn-danger-cyber btn-sm btn-delete" title="Delete">
                                <i class="bi bi-trash"></i>
                            </button>
                        </form>
                    </td>
                    <?php endif; ?>
                </tr>
                <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Pagination -->
<?php if ($totalPages > 1): ?>
<div class="mt-3">
    <?= paginationLinks($currentPage, $totalPages, $baseUrl) ?>
</div>
<?php endif; ?>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
