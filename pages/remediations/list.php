<?php
/**
 * CTVLMS — Remediations List
 */

$pageTitle = 'Remediations';
$db        = getDB();
$entity    = 'remediations';

// ---- Handle DELETE via POST ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    validateCSRF();
    if (!canWrite($entity)) {
        flash('danger', 'Access denied.');
        redirect('?page=remediations/list');
    }
    $delId = (int)$_POST['delete_id'];
    $stmt  = $db->prepare('DELETE FROM remediations WHERE remediationID = :id');
    $stmt->execute([':id' => $delId]);
    logAction('DELETE', 'remediations', $delId, 'Deleted remediation');
    flash('success', 'Remediation deleted successfully.');
    redirect('?page=remediations/list');
}

// ---- Filters ----
$filterType = $_GET['rtype'] ?? '';
$page       = max(1, (int)($_GET['pg'] ?? 1));

$where  = [];
$params = [];

if ($filterType !== '') {
    $where[]           = 'r.remediationType = :rtype';
    $params[':rtype']  = $filterType;
}

$whereSQL = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$countSql = "SELECT COUNT(*) FROM remediations r {$whereSQL}";

$dataSql = "SELECT r.*,
                a.assetName, v.cveID, v.title AS vulnTitle,
                u1.fullName AS assignedToName,
                u2.fullName AS verifiedByName
            FROM remediations r
            LEFT JOIN asset_vulnerabilities av ON r.assetVulnID = av.assetVulnID
            LEFT JOIN assets a ON av.assetID = a.assetID
            LEFT JOIN vulnerabilities v ON av.vulnID = v.vulnID
            LEFT JOIN users u1 ON r.assignedToUserID = u1.userID
            LEFT JOIN users u2 ON r.verifiedByUserID = u2.userID
            {$whereSQL}
            ORDER BY r.startedDate DESC, r.remediationID DESC";

$result      = paginate($db, $countSql, $dataSql, $params, $page, 15);
$rows        = $result['rows'];
$totalPages  = $result['pages'];
$currentPage = $result['current'];

// Build base URL for pagination
$baseUrl = '?page=remediations/list';
if ($filterType !== '') $baseUrl .= '&rtype=' . urlencode($filterType);

$remTypes = ['Patch', 'Configuration_Change', 'Compensating_Control', 'Decommission', 'Risk_Acceptance'];

require __DIR__ . '/../../includes/header.php';
?>

<!-- Page Header -->
<div class="page-header">
    <div>
        <h1 class="h3 mb-0"><i class="bi bi-wrench me-2"></i><?= e($pageTitle) ?></h1>
        <small class="text-muted"><?= $result['total'] ?> remediation<?= $result['total'] !== 1 ? 's' : '' ?> found</small>
    </div>
    <?php if (canWrite($entity)): ?>
    <a href="?page=remediations/form" class="btn btn-cyber">
        <i class="bi bi-plus-lg me-1"></i> New Remediation
    </a>
    <?php endif; ?>
</div>

<!-- Filters -->
<div class="filter-bar glass-card p-3 mb-4">
    <form method="GET" class="row g-2 align-items-end">
        <input type="hidden" name="page" value="remediations/list">
        <div class="col-md-3">
            <label class="form-label small text-muted">Remediation Type</label>
            <select name="rtype" class="form-select form-select-sm">
                <option value="">All Types</option>
                <?php foreach ($remTypes as $rt): ?>
                <option value="<?= e($rt) ?>" <?= $filterType === $rt ? 'selected' : '' ?>>
                    <?= e(str_replace('_', ' ', $rt)) ?>
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
            <a href="?page=remediations/list" class="btn btn-outline-secondary btn-sm flex-fill">
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
                    <th>Asset — Vulnerability</th>
                    <th>Assigned To</th>
                    <th>Type</th>
                    <th>Action Taken</th>
                    <th>Started</th>
                    <th>Completed</th>
                    <th>Verified By</th>
                    <th>Verification</th>
                    <?php if (canWrite($entity)): ?>
                    <th class="text-end">Actions</th>
                    <?php endif; ?>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($rows)): ?>
                <tr>
                    <td colspan="<?= canWrite($entity) ? 9 : 8 ?>" class="text-center py-5">
                        <div class="empty-state">
                            <i class="bi bi-wrench-adjustable" style="font-size:2.5rem;color:var(--accent-cyan);"></i>
                            <p class="mt-2 mb-0 text-muted">No remediations found.</p>
                        </div>
                    </td>
                </tr>
                <?php else: ?>
                <?php foreach ($rows as $row): ?>
                <tr>
                    <td>
                        <div>
                            <strong><?= e($row['assetName'] ?? 'Unknown Asset') ?></strong>
                        </div>
                        <small class="text-muted font-mono">
                            <?= e($row['cveID'] ?? '') ?>
                            <?php if (!empty($row['vulnTitle'])): ?>
                                — <?= e(substr($row['vulnTitle'], 0, 40)) ?><?= strlen($row['vulnTitle'] ?? '') > 40 ? '…' : '' ?>
                            <?php endif; ?>
                        </small>
                    </td>
                    <td><?= e($row['assignedToName'] ?? '—') ?></td>
                    <td>
                        <?php
                        $typeColors = [
                            'Patch'                 => 'bg-success',
                            'Configuration_Change'  => 'bg-info',
                            'Compensating_Control'  => 'bg-warning text-dark',
                            'Decommission'          => 'bg-danger',
                            'Risk_Acceptance'       => 'bg-secondary',
                        ];
                        $cls = $typeColors[$row['remediationType']] ?? 'bg-secondary';
                        ?>
                        <span class="badge <?= $cls ?>"><?= e(str_replace('_', ' ', $row['remediationType'] ?? '')) ?></span>
                    </td>
                    <td>
                        <?php
                        $action = $row['actionTaken'] ?? '';
                        echo e(strlen($action) > 50 ? substr($action, 0, 50) . '…' : $action);
                        ?>
                    </td>
                    <td class="font-mono"><?= e($row['startedDate'] ?? '—') ?></td>
                    <td class="font-mono"><?= e($row['completedDate'] ?? '—') ?></td>
                    <td><?= e($row['verifiedByName'] ?? '—') ?></td>
                    <td class="font-mono"><?= e($row['verificationDate'] ?? '—') ?></td>
                    <?php if (canWrite($entity)): ?>
                    <td class="text-end text-nowrap">
                        <a href="?page=remediations/form&id=<?= (int)$row['remediationID'] ?>"
                           class="btn btn-cyber-outline btn-sm" title="Edit">
                            <i class="bi bi-pencil"></i>
                        </a>
                        <form method="POST" action="?page=remediations/list" class="d-inline">
                            <?= csrfField() ?>
                            <input type="hidden" name="delete_id" value="<?= (int)$row['remediationID'] ?>">
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
