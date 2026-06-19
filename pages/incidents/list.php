<?php
/**
 * CTVLMS — Incidents: List
 */

$pageTitle = 'Incidents';
$db = getDB();
$entity = 'incidents';

// ---- Handle DELETE via POST ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    validateCSRF();
    if (!canWrite($entity)) {
        flash('danger', 'Access denied.');
        redirect('?page=incidents/list');
    }

    $id = (int)$_POST['delete_id'];
    $stmt = $db->prepare('DELETE FROM incidents WHERE incidentID = :id');
    $stmt->execute([':id' => $id]);
    logAction('DELETE', 'incidents', $id, 'Deleted incident');
    flash('success', 'Incident deleted successfully.');
    redirect('?page=incidents/list');
}

// ---- Filters ----
$filterSeverity = $_GET['severity'] ?? '';
$filterStatus   = $_GET['status'] ?? '';

$severities = ['Low', 'Medium', 'High', 'Critical'];
$statuses   = ['Open', 'Investigating', 'Contained', 'Eradicated', 'Recovered', 'Closed'];

$where  = [];
$params = [];

if ($filterSeverity !== '' && in_array($filterSeverity, $severities, true)) {
    $where[]  = 'inc.severity = :sev';
    $params[':sev'] = $filterSeverity;
}
if ($filterStatus !== '' && in_array($filterStatus, $statuses, true)) {
    $where[] = 'inc.status = :stat';
    $params[':stat'] = $filterStatus;
}

$whereClause = $where ? ' WHERE ' . implode(' AND ', $where) : '';

// ---- Pagination ----
$page    = max(1, (int)($_GET['pg'] ?? 1));
$perPage = 15;

$countSql = "SELECT COUNT(*)
               FROM incidents inc"
            . $whereClause;

$dataSql  = "SELECT inc.*,
                    a.assetName,
                    t.actorName,
                    u.fullName AS assignedToName
               FROM incidents inc
               JOIN assets a ON inc.assetID = a.assetID
               LEFT JOIN threat_actors t ON inc.actorID = t.actorID
               LEFT JOIN users u ON inc.assignedToUserID = u.userID"
            . $whereClause
            . " ORDER BY FIELD(inc.severity, 'Critical', 'High', 'Medium', 'Low'), inc.detectedDate DESC";

$result = paginate($db, $countSql, $dataSql, $params, $page, $perPage);
$rows   = $result['rows'];

// Build filter base URL
$filterBase = '?page=incidents/list';
if ($filterSeverity !== '') $filterBase .= '&severity=' . urlencode($filterSeverity);
if ($filterStatus !== '')   $filterBase .= '&status=' . urlencode($filterStatus);

// CSRF token for inline updates
$csrfToken = generateCSRFToken();

require __DIR__ . '/../../includes/header.php';
?>

<!-- Page Header -->
<div class="page-header">
    <div>
        <h1 class="h3 mb-0"><i class="bi bi-exclamation-triangle me-2"></i><?= e($pageTitle) ?></h1>
        <small class="text-muted"><?= $result['total'] ?> incident<?= $result['total'] !== 1 ? 's' : '' ?> recorded</small>
    </div>
    <?php if (canWrite($entity)): ?>
    <a href="?page=incidents/form" class="btn btn-cyber">
        <i class="bi bi-plus-lg me-1"></i> Log Incident
    </a>
    <?php endif; ?>
</div>

<!-- Filters -->
<div class="filter-bar mb-3">
    <form method="GET" class="row g-2 align-items-end">
        <input type="hidden" name="page" value="incidents/list">

        <div class="col-md-3">
            <div class="input-group">
                <span class="input-group-text bg-transparent border-secondary"><i class="bi bi-search text-muted"></i></span>
                <input type="text" id="tableSearch" class="form-control bg-transparent border-secondary text-light"
                       placeholder="Search incidents...">
            </div>
        </div>
        <div class="col-md-2">
            <select name="severity" class="form-select bg-transparent border-secondary text-light">
                <option value="">All Severities</option>
                <?php foreach ($severities as $s): ?>
                <option value="<?= e($s) ?>" <?= $filterSeverity === $s ? 'selected' : '' ?>>
                    <?= e($s) ?>
                </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-md-2">
            <select name="status" class="form-select bg-transparent border-secondary text-light">
                <option value="">All Statuses</option>
                <?php foreach ($statuses as $st): ?>
                <option value="<?= e($st) ?>" <?= $filterStatus === $st ? 'selected' : '' ?>>
                    <?= e(str_replace('_', ' ', $st)) ?>
                </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-md-auto">
            <button type="submit" class="btn btn-cyber-outline"><i class="bi bi-funnel me-1"></i>Filter</button>
            <a href="?page=incidents/list" class="btn btn-outline-secondary ms-1">Clear</a>
        </div>
    </form>
</div>

<!-- Table -->
<div class="glass-card p-0 fade-in-up">
    <div class="table-responsive">
        <table class="table table-dark-custom table-hover mb-0">
            <thead>
                <tr>
                    <th>Title</th>
                    <th>Asset</th>
                    <th>Threat Actor</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Detected</th>
                    <th>Assigned To</th>
                    <th>Closed</th>
                    <?php if (canWrite($entity)): ?>
                    <th class="text-end" style="width:120px;">Actions</th>
                    <?php endif; ?>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($rows)): ?>
                <tr>
                    <td colspan="<?= canWrite($entity) ? 9 : 8 ?>" class="text-center py-5">
                        <div class="empty-state">
                            <i class="bi bi-exclamation-triangle" style="font-size:2.5rem;opacity:0.3;"></i>
                            <p class="text-muted mt-2 mb-0">No incidents found.</p>
                        </div>
                    </td>
                </tr>
                <?php else: ?>
                <?php foreach ($rows as $row): ?>
                <tr>
                    <td>
                        <strong><?= e($row['title']) ?></strong>
                    </td>
                    <td><?= e($row['assetName']) ?></td>
                    <td>
                        <?php if (!empty($row['actorName'])): ?>
                            <a href="?page=threat_actors/form&id=<?= (int)$row['actorID'] ?>" class="text-decoration-none">
                                <?= e($row['actorName']) ?>
                            </a>
                        <?php else: ?>
                            <span class="text-muted fst-italic">Unknown</span>
                        <?php endif; ?>
                    </td>
                    <td><?= severityBadge($row['severity']) ?></td>
                    <td>
                        <?php if (canWrite($entity)): ?>
                        <select class="form-select form-select-sm status-select bg-transparent border-secondary text-light"
                                data-id="<?= (int)$row['incidentID'] ?>"
                                data-page="incidents"
                                data-csrf="<?= e($csrfToken) ?>"
                                style="width:auto;min-width:140px;font-size:0.8rem;">
                            <?php foreach ($statuses as $st): ?>
                            <option value="<?= e($st) ?>" <?= $row['status'] === $st ? 'selected' : '' ?>>
                                <?= e(str_replace('_', ' ', $st)) ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                        <?php else: ?>
                            <?= statusBadge($row['status']) ?>
                        <?php endif; ?>
                    </td>
                    <td><?= e($row['detectedDate'] ? date('Y-m-d', strtotime($row['detectedDate'])) : '—') ?></td>
                    <td><?= e($row['assignedToName'] ?? '—') ?></td>
                    <td><?= e($row['closedDate'] ? date('Y-m-d', strtotime($row['closedDate'])) : '—') ?></td>
                    <?php if (canWrite($entity)): ?>
                    <td class="text-end text-nowrap">
                        <a href="?page=incidents/form&id=<?= (int)$row['incidentID'] ?>" class="btn btn-sm btn-cyber-outline" title="Edit">
                            <i class="bi bi-pencil"></i>
                        </a>
                        <form method="POST" action="?page=incidents/list" class="d-inline">
                            <?= csrfField() ?>
                            <input type="hidden" name="delete_id" value="<?= (int)$row['incidentID'] ?>">
                            <button type="submit" class="btn btn-sm btn-danger-cyber btn-delete" title="Delete">
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
<?= paginationLinks($result['current'], $result['pages'], $filterBase) ?>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
