<?php
/**
 * CTVLMS — Threat Actors: List
 */

$pageTitle = 'Threat Actors';
$db = getDB();
$entity = 'threat_actors';

// ---- Handle DELETE via POST ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    validateCSRF();
    if (!canWrite($entity)) {
        flash('danger', 'Access denied.');
        redirect('?page=threat_actors/list');
    }

    $id = (int)$_POST['delete_id'];

    // Check for linked IOCs before deleting
    $check = $db->prepare('SELECT COUNT(*) FROM indicators_of_compromise WHERE actorID = :id');
    $check->execute([':id' => $id]);
    if ((int)$check->fetchColumn() > 0) {
        flash('danger', 'Cannot delete: this threat actor has linked IOCs. Remove them first.');
        redirect('?page=threat_actors/list');
    }

    // Check for linked incidents
    $check2 = $db->prepare('SELECT COUNT(*) FROM incidents WHERE actorID = :id');
    $check2->execute([':id' => $id]);
    if ((int)$check2->fetchColumn() > 0) {
        flash('danger', 'Cannot delete: this threat actor is linked to incidents. Remove them first.');
        redirect('?page=threat_actors/list');
    }

    $stmt = $db->prepare('DELETE FROM threat_actors WHERE actorID = :id');
    $stmt->execute([':id' => $id]);
    logAction('DELETE', 'threat_actors', $id, 'Deleted threat actor');
    flash('success', 'Threat actor deleted successfully.');
    redirect('?page=threat_actors/list');
}

// ---- Pagination ----
$page = max(1, (int)($_GET['pg'] ?? 1));
$perPage = 15;

$countSql = 'SELECT COUNT(*) FROM threat_actors';
$dataSql  = 'SELECT * FROM threat_actors ORDER BY actorName ASC';
$result   = paginate($db, $countSql, $dataSql, [], $page, $perPage);
$rows     = $result['rows'];

require __DIR__ . '/../../includes/header.php';
?>

<!-- Page Header -->
<div class="page-header">
    <div>
        <h1 class="h3 mb-0"><i class="bi bi-person-badge me-2"></i><?= e($pageTitle) ?></h1>
        <small class="text-muted"><?= $result['total'] ?> threat actor<?= $result['total'] !== 1 ? 's' : '' ?> tracked</small>
    </div>
    <?php if (canWrite($entity)): ?>
    <a href="?page=threat_actors/form" class="btn btn-cyber">
        <i class="bi bi-plus-lg me-1"></i> Add Threat Actor
    </a>
    <?php endif; ?>
</div>

<!-- Search Bar -->
<div class="filter-bar mb-3">
    <div class="row g-2">
        <div class="col-md-4">
            <div class="input-group">
                <span class="input-group-text bg-transparent border-secondary"><i class="bi bi-search text-muted"></i></span>
                <input type="text" id="tableSearch" class="form-control bg-transparent border-secondary text-light"
                       placeholder="Search threat actors...">
            </div>
        </div>
    </div>
</div>

<!-- Table -->
<div class="glass-card p-0 fade-in-up">
    <div class="table-responsive">
        <table class="table table-dark-custom table-hover mb-0">
            <thead>
                <tr>
                    <th>Actor Name</th>
                    <th>Aliases</th>
                    <th>Motivation</th>
                    <th>Origin Country</th>
                    <th>Description</th>
                    <?php if (canWrite($entity)): ?>
                    <th class="text-end" style="width:120px;">Actions</th>
                    <?php endif; ?>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($rows)): ?>
                <tr>
                    <td colspan="<?= canWrite($entity) ? 6 : 5 ?>" class="text-center py-5">
                        <div class="empty-state">
                            <i class="bi bi-person-badge" style="font-size:2.5rem;opacity:0.3;"></i>
                            <p class="text-muted mt-2 mb-0">No threat actors found.</p>
                        </div>
                    </td>
                </tr>
                <?php else: ?>
                <?php foreach ($rows as $row): ?>
                <tr>
                    <td>
                        <strong><?= e($row['actorName']) ?></strong>
                    </td>
                    <td>
                        <?php if (!empty($row['aliasNames'])): ?>
                            <span class="text-muted font-mono" style="font-size:0.85rem;"><?= e($row['aliasNames']) ?></span>
                        <?php else: ?>
                            <span class="text-muted">—</span>
                        <?php endif; ?>
                    </td>
                    <td><?= motivationBadge($row['motivation']) ?></td>
                    <td><?= e($row['originCountry'] ?: '—') ?></td>
                    <td>
                        <span title="<?= e($row['description'] ?? '') ?>">
                            <?= e($row['description'] ? (mb_strlen($row['description']) > 80 ? mb_substr($row['description'], 0, 80) . '…' : $row['description']) : '—') ?>
                        </span>
                    </td>
                    <?php if (canWrite($entity)): ?>
                    <td class="text-end text-nowrap">
                        <a href="?page=threat_actors/form&id=<?= (int)$row['actorID'] ?>" class="btn btn-sm btn-cyber-outline" title="Edit">
                            <i class="bi bi-pencil"></i>
                        </a>
                        <form method="POST" action="?page=threat_actors/list" class="d-inline">
                            <?= csrfField() ?>
                            <input type="hidden" name="delete_id" value="<?= (int)$row['actorID'] ?>">
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
<?= paginationLinks($result['current'], $result['pages'], '?page=threat_actors/list') ?>

<?php
/**
 * Motivation badge helper (local to this page set).
 */
function motivationBadge(?string $motivation): string
{
    $map = [
        'Financial'  => 'bg-success',
        'Espionage'  => 'bg-danger',
        'Hacktivism' => 'bg-info',
        'Disruption' => 'bg-warning text-dark',
        'Unknown'    => 'bg-secondary',
    ];
    $cls = $map[$motivation] ?? 'bg-secondary';
    return '<span class="badge ' . $cls . '">' . e($motivation ?? 'Unknown') . '</span>';
}

require __DIR__ . '/../../includes/footer.php';
?>
