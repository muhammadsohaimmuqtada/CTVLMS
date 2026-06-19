<?php
/**
 * CTVLMS — Engagements Create / Edit Form
 */

$pageTitle = 'Engagement';
$db        = getDB();
$entity    = 'engagements';
$id        = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$isEdit    = $id > 0;

if (!canWrite($entity)) {
    flash('danger', 'Access denied.');
    redirect('?page=engagements/list');
}

// ---- Handle inline status update (AJAX from list page) ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['inline_status'])) {
    validateCSRF();
    $inId     = (int)$_POST['id'];
    $inStatus = $_POST['status'];
    $allowed  = ['Planned', 'In_Progress', 'Completed', 'Cancelled'];
    if (in_array($inStatus, $allowed, true)) {
        $stmt = $db->prepare('UPDATE engagements SET status = :s WHERE engagementID = :id');
        $stmt->execute([':s' => $inStatus, ':id' => $inId]);
        logAction('UPDATE', 'engagements', $inId, 'Inline status → ' . $inStatus);
        http_response_code(200);
    } else {
        http_response_code(400);
    }
    exit;
}

// ---- Load existing record for edit ----
$record = null;
$selectedAssets = [];
if ($isEdit) {
    $stmt = $db->prepare('SELECT * FROM engagements WHERE engagementID = :id');
    $stmt->execute([':id' => $id]);
    $record = $stmt->fetch();
    if (!$record) {
        flash('danger', 'Engagement not found.');
        redirect('?page=engagements/list');
    }
    $pageTitle = 'Edit Engagement';

    // Load currently linked assets
    $stmt = $db->prepare('SELECT assetID FROM engagement_assets WHERE engagementID = :id');
    $stmt->execute([':id' => $id]);
    $selectedAssets = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
} else {
    $pageTitle = 'New Engagement';
}

// ---- Handle form submission ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['inline_status'])) {
    validateCSRF();

    $data = [
        'engagementName' => trim($_POST['engagementName'] ?? ''),
        'engagementType' => $_POST['engagementType'] ?? '',
        'leadUserID'     => ($_POST['leadUserID'] ?? '') !== '' ? (int)$_POST['leadUserID'] : null,
        'startDate'      => $_POST['startDate'] ?? null,
        'endDate'        => $_POST['endDate'] ?? null,
        'status'         => $_POST['status'] ?? 'Planned',
        'scopeSummary'   => trim($_POST['scopeSummary'] ?? ''),
    ];

    // Validation
    $errors = [];
    if ($data['engagementName'] === '') {
        $errors[] = 'Engagement name is required.';
    }
    $allowedTypes    = ['Pentest', 'Red_Team', 'Purple_Team', 'Vuln_Assessment'];
    $allowedStatuses = ['Planned', 'In_Progress', 'Completed', 'Cancelled'];
    if (!in_array($data['engagementType'], $allowedTypes, true)) {
        $errors[] = 'Invalid engagement type.';
    }
    if (!in_array($data['status'], $allowedStatuses, true)) {
        $errors[] = 'Invalid status.';
    }
    if ($data['startDate'] === '') $data['startDate'] = null;
    if ($data['endDate'] === '')   $data['endDate']   = null;

    $postedAssets = $_POST['scoped_assets'] ?? [];
    $postedAssets = array_map('intval', $postedAssets);

    if (empty($errors)) {
        if ($isEdit) {
            $stmt = $db->prepare(
                'UPDATE engagements SET
                    engagementName = :name, engagementType = :type,
                    leadUserID = :lead, startDate = :sd, endDate = :ed,
                    status = :st, scopeSummary = :scope
                 WHERE engagementID = :id'
            );
            $stmt->execute([
                ':name'  => $data['engagementName'],
                ':type'  => $data['engagementType'],
                ':lead'  => $data['leadUserID'],
                ':sd'    => $data['startDate'],
                ':ed'    => $data['endDate'],
                ':st'    => $data['status'],
                ':scope' => $data['scopeSummary'],
                ':id'    => $id,
            ]);
            logAction('UPDATE', 'engagements', $id, 'Updated engagement: ' . $data['engagementName']);
        } else {
            $stmt = $db->prepare(
                'INSERT INTO engagements
                    (engagementName, engagementType, leadUserID, startDate, endDate, status, scopeSummary)
                 VALUES (:name, :type, :lead, :sd, :ed, :st, :scope)'
            );
            $stmt->execute([
                ':name'  => $data['engagementName'],
                ':type'  => $data['engagementType'],
                ':lead'  => $data['leadUserID'],
                ':sd'    => $data['startDate'],
                ':ed'    => $data['endDate'],
                ':st'    => $data['status'],
                ':scope' => $data['scopeSummary'],
            ]);
            $id = (int)$db->lastInsertId();
            logAction('INSERT', 'engagements', $id, 'Created engagement: ' . $data['engagementName']);
        }

        // ---- Sync engagement_assets junction table ----
        $stmt = $db->prepare('DELETE FROM engagement_assets WHERE engagementID = :id');
        $stmt->execute([':id' => $id]);

        if (!empty($postedAssets)) {
            $ins = $db->prepare('INSERT INTO engagement_assets (engagementID, assetID) VALUES (:eid, :aid)');
            foreach ($postedAssets as $aid) {
                $ins->execute([':eid' => $id, ':aid' => $aid]);
            }
        }
        logAction('UPDATE', 'engagement_assets', $id, 'Synced ' . count($postedAssets) . ' scoped assets');

        flash('success', 'Engagement ' . ($isEdit ? 'updated' : 'created') . ' successfully.');
        redirect('?page=engagements/list');
    } else {
        foreach ($errors as $err) {
            flash('danger', $err);
        }
        // Preserve form state
        $record = $data;
        $record['engagementID'] = $id;
        $selectedAssets = $postedAssets;
    }
}

// ---- Load lookup data ----
$users  = $db->query('SELECT userID, fullName FROM users WHERE isActive = 1 ORDER BY fullName')->fetchAll();
$assets = $db->query('SELECT assetID, assetName, assetType, environment FROM assets ORDER BY assetName')->fetchAll();

$types    = ['Pentest', 'Red_Team', 'Purple_Team', 'Vuln_Assessment'];
$statuses = ['Planned', 'In_Progress', 'Completed', 'Cancelled'];

require __DIR__ . '/../../includes/header.php';
?>

<!-- Page Header -->
<div class="page-header">
    <div>
        <h1 class="h3 mb-0">
            <i class="bi bi-calendar-check me-2"></i>
            <?= e($pageTitle) ?>
        </h1>
        <small class="text-muted">
            <a href="?page=engagements/list" class="text-decoration-none text-muted">
                <i class="bi bi-arrow-left me-1"></i>Back to Engagements
            </a>
        </small>
    </div>
</div>

<!-- Form -->
<div class="glass-card p-4 fade-in-up" style="max-width: 900px;">
    <form method="POST" action="?page=engagements/form<?= $isEdit ? '&id=' . $id : '' ?>">
        <?= csrfField() ?>

        <div class="row g-3">
            <!-- Engagement Name -->
            <div class="col-md-8">
                <label for="engagementName" class="form-label">Engagement Name <span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="engagementName" name="engagementName"
                       value="<?= e($record['engagementName'] ?? '') ?>" required>
            </div>

            <!-- Engagement Type -->
            <div class="col-md-4">
                <label for="engagementType" class="form-label">Type <span class="text-danger">*</span></label>
                <select class="form-select" id="engagementType" name="engagementType" required>
                    <option value="">— Select Type —</option>
                    <?php foreach ($types as $t): ?>
                    <option value="<?= e($t) ?>"
                        <?= ($record['engagementType'] ?? '') === $t ? 'selected' : '' ?>>
                        <?= e(str_replace('_', ' ', $t)) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Lead User -->
            <div class="col-md-4">
                <label for="leadUserID" class="form-label">Lead</label>
                <select class="form-select" id="leadUserID" name="leadUserID">
                    <option value="">— Unassigned —</option>
                    <?php foreach ($users as $u): ?>
                    <option value="<?= (int)$u['userID'] ?>"
                        <?= ((int)($record['leadUserID'] ?? 0)) === (int)$u['userID'] ? 'selected' : '' ?>>
                        <?= e($u['fullName']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Start Date -->
            <div class="col-md-4">
                <label for="startDate" class="form-label">Start Date</label>
                <input type="date" class="form-control" id="startDate" name="startDate"
                       value="<?= e($record['startDate'] ?? '') ?>">
            </div>

            <!-- End Date -->
            <div class="col-md-4">
                <label for="endDate" class="form-label">End Date</label>
                <input type="date" class="form-control" id="endDate" name="endDate"
                       value="<?= e($record['endDate'] ?? '') ?>">
            </div>

            <!-- Status -->
            <div class="col-md-4">
                <label for="status" class="form-label">Status</label>
                <select class="form-select" id="status" name="status">
                    <?php foreach ($statuses as $s): ?>
                    <option value="<?= e($s) ?>"
                        <?= ($record['status'] ?? 'Planned') === $s ? 'selected' : '' ?>>
                        <?= e(str_replace('_', ' ', $s)) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Scope Summary -->
            <div class="col-12">
                <label for="scopeSummary" class="form-label">Scope Summary</label>
                <textarea class="form-control" id="scopeSummary" name="scopeSummary"
                          rows="3" placeholder="Describe the scope of this engagement…"><?= e($record['scopeSummary'] ?? '') ?></textarea>
            </div>

            <!-- Scoped Assets (multi-select checklist) -->
            <div class="col-12">
                <label class="form-label">Scoped Assets</label>
                <div class="glass-card p-3" style="max-height: 260px; overflow-y: auto; background: rgba(0,0,0,0.2);">
                    <?php if (empty($assets)): ?>
                    <p class="text-muted mb-0 small">No assets available. Create assets first.</p>
                    <?php else: ?>
                    <div class="row g-2">
                        <?php foreach ($assets as $a): ?>
                        <div class="col-md-6 col-lg-4">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox"
                                       name="scoped_assets[]"
                                       value="<?= (int)$a['assetID'] ?>"
                                       id="asset_<?= (int)$a['assetID'] ?>"
                                    <?= in_array((int)$a['assetID'], $selectedAssets, true) ? 'checked' : '' ?>>
                                <label class="form-check-label small" for="asset_<?= (int)$a['assetID'] ?>">
                                    <?= e($a['assetName']) ?>
                                    <span class="text-muted">(<?= e(str_replace('_', ' ', $a['assetType'])) ?>)</span>
                                </label>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                </div>
                <small class="text-muted">Select assets in scope for this engagement.</small>
            </div>
        </div>

        <!-- Actions -->
        <div class="d-flex justify-content-between align-items-center mt-4 pt-3 border-top border-secondary">
            <a href="?page=engagements/list" class="btn btn-outline-secondary">
                <i class="bi bi-x-lg me-1"></i> Cancel
            </a>
            <button type="submit" class="btn btn-cyber">
                <i class="bi bi-check-lg me-1"></i>
                <?= $isEdit ? 'Update Engagement' : 'Create Engagement' ?>
            </button>
        </div>
    </form>
</div>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
