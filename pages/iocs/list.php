<?php
/**
 * CTVLMS — Indicators of Compromise: List
 */

$pageTitle = 'Indicators of Compromise';
$db = getDB();
$entity = 'iocs';

// ---- Handle DELETE via POST ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    validateCSRF();
    if (!canWrite($entity)) {
        flash('danger', 'Access denied.');
        redirect('?page=iocs/list');
    }

    $id = (int)$_POST['delete_id'];
    $stmt = $db->prepare('DELETE FROM indicators_of_compromise WHERE iocID = :id');
    $stmt->execute([':id' => $id]);
    logAction('DELETE', 'indicators_of_compromise', $id, 'Deleted IOC');
    flash('success', 'IOC deleted successfully.');
    redirect('?page=iocs/list');
}

// ---- Filters ----
$filterType       = $_GET['iocType'] ?? '';
$filterConfidence = $_GET['confidence'] ?? '';

$iocTypes         = ['IP', 'Domain', 'URL', 'File_Hash', 'Email', 'Registry_Key'];
$confidenceLevels = ['Low', 'Medium', 'High'];

$where  = [];
$params = [];

if ($filterType !== '' && in_array($filterType, $iocTypes, true)) {
    $where[]  = 'i.iocType = :iocType';
    $params[':iocType'] = $filterType;
}
if ($filterConfidence !== '' && in_array($filterConfidence, $confidenceLevels, true)) {
    $where[] = 'i.confidenceLevel = :conf';
    $params[':conf'] = $filterConfidence;
}

$whereClause = $where ? ' WHERE ' . implode(' AND ', $where) : '';

// ---- Pagination ----
$page    = max(1, (int)($_GET['pg'] ?? 1));
$perPage = 15;

$countSql = "SELECT COUNT(*) FROM indicators_of_compromise i" . $whereClause;
$dataSql  = "SELECT i.*, t.actorName
               FROM indicators_of_compromise i
               LEFT JOIN threat_actors t ON i.actorID = t.actorID"
            . $whereClause
            . " ORDER BY i.lastSeen DESC, i.firstSeen DESC";

$result = paginate($db, $countSql, $dataSql, $params, $page, $perPage);
$rows   = $result['rows'];

// Build filter base URL
$filterBase = '?page=iocs/list';
if ($filterType !== '')       $filterBase .= '&iocType=' . urlencode($filterType);
if ($filterConfidence !== '') $filterBase .= '&confidence=' . urlencode($filterConfidence);

require __DIR__ . '/../../includes/header.php';
?>

<!-- Page Header -->
<div class="page-header">
    <div>
        <h1 class="h3 mb-0"><i class="bi bi-fingerprint me-2"></i><?= e($pageTitle) ?></h1>
        <small class="text-muted"><?= $result['total'] ?> indicator<?= $result['total'] !== 1 ? 's' : '' ?> catalogued</small>
    </div>
    <?php if (canWrite($entity)): ?>
    <a href="?page=iocs/form" class="btn btn-cyber">
        <i class="bi bi-plus-lg me-1"></i> Add IOC
    </a>
    <?php endif; ?>
</div>

<!-- Filters -->
<div class="filter-bar mb-3">
    <form method="GET" class="row g-2 align-items-end">
        <input type="hidden" name="page" value="iocs/list">

        <div class="col-md-3">
            <div class="input-group">
                <span class="input-group-text bg-transparent border-secondary"><i class="bi bi-search text-muted"></i></span>
                <input type="text" id="tableSearch" class="form-control bg-transparent border-secondary text-light"
                       placeholder="Search IOCs...">
            </div>
        </div>
        <div class="col-md-2">
            <select name="iocType" class="form-select bg-transparent border-secondary text-light">
                <option value="">All Types</option>
                <?php foreach ($iocTypes as $t): ?>
                <option value="<?= e($t) ?>" <?= $filterType === $t ? 'selected' : '' ?>>
                    <?= e(str_replace('_', ' ', $t)) ?>
                </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-md-2">
            <select name="confidence" class="form-select bg-transparent border-secondary text-light">
                <option value="">All Confidence</option>
                <?php foreach ($confidenceLevels as $c): ?>
                <option value="<?= e($c) ?>" <?= $filterConfidence === $c ? 'selected' : '' ?>>
                    <?= e($c) ?>
                </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-md-auto">
            <button type="submit" class="btn btn-cyber-outline"><i class="bi bi-funnel me-1"></i>Filter</button>
            <a href="?page=iocs/list" class="btn btn-outline-secondary ms-1">Clear</a>
        </div>
    </form>
</div>

<!-- Table -->
<div class="glass-card p-0 fade-in-up">
    <div class="table-responsive">
        <table class="table table-dark-custom table-hover mb-0">
            <thead>
                <tr>
                    <th>IOC Value</th>
                    <th>Type</th>
                    <th>Threat Actor</th>
                    <th>MITRE Technique</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>Confidence</th>
                    <?php if (canWrite($entity)): ?>
                    <th class="text-end" style="width:120px;">Actions</th>
                    <?php endif; ?>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($rows)): ?>
                <tr>
                    <td colspan="<?= canWrite($entity) ? 8 : 7 ?>" class="text-center py-5">
                        <div class="empty-state">
                            <i class="bi bi-fingerprint" style="font-size:2.5rem;opacity:0.3;"></i>
                            <p class="text-muted mt-2 mb-0">No indicators of compromise found.</p>
                        </div>
                    </td>
                </tr>
                <?php else: ?>
                <?php foreach ($rows as $row): ?>
                <tr>
                    <td><span class="font-mono"><?= e($row['iocValue']) ?></span></td>
                    <td><?= iocTypeBadge($row['iocType']) ?></td>
                    <td>
                        <?php if (!empty($row['actorName'])): ?>
                            <a href="?page=threat_actors/form&id=<?= (int)$row['actorID'] ?>" class="text-decoration-none">
                                <?= e($row['actorName']) ?>
                            </a>
                        <?php else: ?>
                            <span class="text-muted fst-italic">Unattributed</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php if (!empty($row['mitreTechnique'])): ?>
                            <span class="font-mono"><?= e($row['mitreTechnique']) ?></span>
                        <?php else: ?>
                            <span class="text-muted">—</span>
                        <?php endif; ?>
                    </td>
                    <td><?= e($row['firstSeen'] ? date('Y-m-d', strtotime($row['firstSeen'])) : '—') ?></td>
                    <td><?= e($row['lastSeen'] ? date('Y-m-d', strtotime($row['lastSeen'])) : '—') ?></td>
                    <td><?= confidenceBadge($row['confidenceLevel']) ?></td>
                    <?php if (canWrite($entity)): ?>
                    <td class="text-end text-nowrap">
                        <a href="?page=iocs/form&id=<?= (int)$row['iocID'] ?>" class="btn btn-sm btn-cyber-outline" title="Edit">
                            <i class="bi bi-pencil"></i>
                        </a>
                        <form method="POST" action="?page=iocs/list" class="d-inline">
                            <?= csrfField() ?>
                            <input type="hidden" name="delete_id" value="<?= (int)$row['iocID'] ?>">
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

<?php
/**
 * IOC type badge helper.
 */
function iocTypeBadge(?string $type): string
{
    $map = [
        'IP'           => 'bg-info',
        'Domain'       => 'bg-primary',
        'URL'          => 'bg-warning text-dark',
        'File_Hash'    => 'bg-danger',
        'Email'        => 'bg-success',
        'Registry_Key' => 'bg-secondary',
    ];
    $cls = $map[$type] ?? 'bg-secondary';
    $label = str_replace('_', ' ', $type ?? '');
    return '<span class="badge ' . $cls . '">' . e($label) . '</span>';
}

/**
 * Confidence level badge helper.
 */
function confidenceBadge(?string $level): string
{
    $map = [
        'High'   => 'bg-success',
        'Medium' => 'bg-warning text-dark',
        'Low'    => 'bg-danger',
    ];
    $cls = $map[$level] ?? 'bg-secondary';
    return '<span class="badge ' . $cls . '">' . e($level ?? '—') . '</span>';
}

require __DIR__ . '/../../includes/footer.php';
?>
