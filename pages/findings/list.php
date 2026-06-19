<?php
/**
 * CTVLMS — Findings List
 */

$pageTitle = 'Findings';
$db        = getDB();
$entity    = 'findings';

// ---- Handle DELETE via POST ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    validateCSRF();
    if (!canWrite($entity)) {
        flash('danger', 'Access denied.');
        redirect('?page=findings/list');
    }
    $delId = (int)$_POST['delete_id'];
    $stmt  = $db->prepare('DELETE FROM findings WHERE findingID = :id');
    $stmt->execute([':id' => $delId]);
    logAction('DELETE', 'findings', $delId, 'Deleted finding');
    flash('success', 'Finding deleted successfully.');
    redirect('?page=findings/list');
}

// ---- Filters ----
$filterRisk = $_GET['risk'] ?? '';
$page       = max(1, (int)($_GET['pg'] ?? 1));

$where  = [];
$params = [];

if ($filterRisk !== '') {
    $where[]          = 'f.riskRating = :risk';
    $params[':risk']  = $filterRisk;
}

$whereSQL = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$countSql = "SELECT COUNT(*) FROM findings f {$whereSQL}";

$dataSql = "SELECT f.*, eng.engagementName, a.assetName, u.fullName AS discoveredByName
            FROM findings f
            LEFT JOIN engagements eng ON f.engagementID = eng.engagementID
            LEFT JOIN assets a ON f.assetID = a.assetID
            LEFT JOIN users u ON f.discoveredByUserID = u.userID
            {$whereSQL}
            ORDER BY f.reportedDate DESC, f.findingID DESC";

$result      = paginate($db, $countSql, $dataSql, $params, $page, 15);
$rows        = $result['rows'];
$totalPages  = $result['pages'];
$currentPage = $result['current'];

// Build base URL for pagination
$baseUrl = '?page=findings/list';
if ($filterRisk !== '') $baseUrl .= '&risk=' . urlencode($filterRisk);

$riskLevels = ['Critical', 'High', 'Medium', 'Low'];

require __DIR__ . '/../../includes/header.php';
?>

<!-- Page Header -->
<div class="page-header">
    <div>
        <h1 class="h3 mb-0"><i class="bi bi-search me-2"></i><?= e($pageTitle) ?></h1>
        <small class="text-muted"><?= $result['total'] ?> finding<?= $result['total'] !== 1 ? 's' : '' ?> found</small>
    </div>
    <?php if (canWrite($entity)): ?>
    <a href="?page=findings/form" class="btn btn-cyber">
        <i class="bi bi-plus-lg me-1"></i> New Finding
    </a>
    <?php endif; ?>
</div>

<!-- Filters -->
<div class="filter-bar glass-card p-3 mb-4">
    <form method="GET" class="row g-2 align-items-end">
        <input type="hidden" name="page" value="findings/list">
        <div class="col-md-3">
            <label class="form-label small text-muted">Risk Rating</label>
            <select name="risk" class="form-select form-select-sm">
                <option value="">All Ratings</option>
                <?php foreach ($riskLevels as $r): ?>
                <option value="<?= e($r) ?>" <?= $filterRisk === $r ? 'selected' : '' ?>>
                    <?= e($r) ?>
                </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-md-4">
            <label class="form-label small text-muted">Search</label>
            <input type="text" id="tableSearch" class="form-control form-control-sm"
                   placeholder="Quick filter…">
        </div>
        <div class="col-md-3 d-flex gap-2">
            <button type="submit" class="btn btn-cyber-outline btn-sm flex-fill">
                <i class="bi bi-funnel me-1"></i> Filter
            </button>
            <a href="?page=findings/list" class="btn btn-outline-secondary btn-sm flex-fill">
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
                    <th>Title</th>
                    <th>Engagement</th>
                    <th>Asset</th>
                    <th>Risk Rating</th>
                    <th class="text-center">Exploited</th>
                    <th>Discovered By</th>
                    <th>Reported Date</th>
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
                            <i class="bi bi-binoculars" style="font-size:2.5rem;color:var(--accent-cyan);"></i>
                            <p class="mt-2 mb-0 text-muted">No findings found.</p>
                        </div>
                    </td>
                </tr>
                <?php else: ?>
                <?php foreach ($rows as $row): ?>
                <tr>
                    <td><strong><?= e($row['title']) ?></strong></td>
                    <td><?= e($row['engagementName'] ?? '—') ?></td>
                    <td><?= e($row['assetName'] ?? '—') ?></td>
                    <td><?= severityBadge($row['riskRating']) ?></td>
                    <td class="text-center">
                        <?php if ($row['exploitedSuccessfully']): ?>
                            <span class="text-success fw-bold" title="Exploited"><i class="bi bi-check-circle-fill"></i> ✓</span>
                        <?php else: ?>
                            <span class="text-danger" title="Not Exploited"><i class="bi bi-x-circle-fill"></i> ✗</span>
                        <?php endif; ?>
                    </td>
                    <td><?= e($row['discoveredByName'] ?? '—') ?></td>
                    <td class="font-mono"><?= e($row['reportedDate'] ?? '—') ?></td>
                    <?php if (canWrite($entity)): ?>
                    <td class="text-end text-nowrap">
                        <a href="?page=findings/form&id=<?= (int)$row['findingID'] ?>"
                           class="btn btn-cyber-outline btn-sm" title="Edit">
                            <i class="bi bi-pencil"></i>
                        </a>
                        <form method="POST" action="?page=findings/list" class="d-inline">
                            <?= csrfField() ?>
                            <input type="hidden" name="delete_id" value="<?= (int)$row['findingID'] ?>">
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
