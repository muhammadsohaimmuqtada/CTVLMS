<?php
$pageTitle = 'Asset Vulnerability';
$db = getDB();
$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$isEdit = $id > 0;
$entity = 'asset_vulns';

if (!canWrite($entity)) {
    flash('danger', 'Access denied.');
    redirect("?page={$entity}/list");
}

$statuses = lifecycleStatuses();

// Handle inline status update (AJAX from list page)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['inline_status'])) {
    validateCSRF();

    $targetId  = (int)($_POST['id'] ?? 0);
    $newStatus = $_POST['inline_status'] ?? '';

    if ($targetId <= 0 || !in_array($newStatus, $statuses, true)) {
        http_response_code(400);
        echo 'Invalid input';
        exit;
    }

    $stmt = $db->prepare('SELECT status, closedDate, notes FROM asset_vulnerabilities WHERE assetVulnID = :id');
    $stmt->execute([':id' => $targetId]);
    $current = $stmt->fetch();
    if (!$current) {
        http_response_code(404);
        echo 'Record not found';
        exit;
    }

    $oldStatus = $current['status'];
    $error = validateLifecycleTransition($db, $targetId, $oldStatus, $newStatus, (string)($current['notes'] ?? ''));
    if ($error !== null) {
        http_response_code(403);
        echo $error;
        exit;
    }

    $closedDate = $current['closedDate'];
    if (terminalLifecycleStatus($newStatus)) {
        $closedDate = $closedDate ?: date('Y-m-d');
    } elseif (terminalLifecycleStatus($oldStatus)) {
        $closedDate = null;
    }

    $stmt = $db->prepare(
        'UPDATE asset_vulnerabilities
         SET status = :status, closedDate = :closed
         WHERE assetVulnID = :id'
    );
    $stmt->execute([':status' => $newStatus, ':closed' => $closedDate, ':id' => $targetId]);

    logAction('STATUS_CHANGE', 'asset_vulnerabilities', $targetId, "Status: {$oldStatus} → {$newStatus}");
    http_response_code(200);
    echo 'OK';
    exit;
}

// Load existing record for edit
$record = null;
if ($isEdit) {
    $stmt = $db->prepare('SELECT * FROM asset_vulnerabilities WHERE assetVulnID = :id');
    $stmt->execute([':id' => $id]);
    $record = $stmt->fetch();
    if (!$record) {
        flash('danger', 'Record not found.');
        redirect("?page={$entity}/list");
    }
    $pageTitle = 'Edit Asset Vulnerability';
} else {
    $pageTitle = 'Map Vulnerability to Asset';
}

// Fetch dropdown data
$assets = $db->query('SELECT assetID, assetName FROM assets ORDER BY assetName')->fetchAll();
$vulns = $db->query('SELECT vulnID, cveID, title FROM vulnerabilities ORDER BY title')->fetchAll();
$users = $db->query('SELECT userID, fullName FROM users WHERE isActive = 1 ORDER BY fullName')->fetchAll();

// Handle form submission
$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['inline_status'])) {
    validateCSRF();

    $assetID         = (int)($_POST['assetID'] ?? 0);
    $vulnID          = (int)($_POST['vulnID'] ?? 0);
    $status          = $_POST['status'] ?? '';
    $discoveredDate  = $_POST['discoveredDate'] ?? '';
    $triagedByUserID = ($_POST['triagedByUserID'] ?? '') !== '' ? (int)$_POST['triagedByUserID'] : null;
    $dueDate         = $_POST['dueDate'] ?? '';
    $notes           = trim($_POST['notes'] ?? '');

    if ($assetID <= 0) $errors[] = 'Asset is required.';
    if ($vulnID <= 0) $errors[] = 'Vulnerability is required.';
    if (!in_array($status, $statuses, true)) $errors[] = 'Invalid status.';
    if ($discoveredDate === '') $errors[] = 'Discovered date is required.';

    if (!$isEdit && $status !== 'Discovered') {
        $errors[] = 'New asset-vulnerability records must begin in Discovered state.';
    }

    if ($isEdit && empty($errors)) {
        $transitionError = validateLifecycleTransition($db, $id, $record['status'], $status, $notes);
        if ($transitionError !== null) {
            $errors[] = $transitionError;
        }
    }

    if ($status === 'Triaged' && $triagedByUserID === null) {
        $triagedByUserID = (int)($_SESSION['user_id'] ?? 0) ?: null;
    }

    $closedDate = $record['closedDate'] ?? null;
    if (terminalLifecycleStatus($status)) {
        $closedDate = $closedDate ?: date('Y-m-d');
    } elseif ($isEdit && terminalLifecycleStatus($record['status'])) {
        $closedDate = null;
    }

    if (empty($errors)) {
        $data = [
            ':asset'      => $assetID,
            ':vuln'       => $vulnID,
            ':status'     => $status,
            ':discovered' => $discoveredDate,
            ':triaged'    => $triagedByUserID,
            ':due'        => $dueDate ?: null,
            ':closed'     => $closedDate,
            ':notes'      => $notes ?: null,
        ];

        try {
            if ($isEdit) {
                $oldStatus = $record['status'];
                $stmt = $db->prepare(
                    'UPDATE asset_vulnerabilities
                     SET assetID = :asset, vulnID = :vuln, status = :status,
                         discoveredDate = :discovered, triagedByUserID = :triaged,
                         dueDate = :due, closedDate = :closed, notes = :notes
                     WHERE assetVulnID = :id'
                );
                $data[':id'] = $id;
                $stmt->execute($data);

                $detail = $oldStatus !== $status
                    ? "Status: {$oldStatus} → {$status}. Updated asset-vulnerability mapping"
                    : 'Updated asset-vulnerability mapping';
                logAction('UPDATE', 'asset_vulnerabilities', $id, $detail);
                flash('success', 'Record updated successfully.');
            } else {
                $stmt = $db->prepare(
                    'INSERT INTO asset_vulnerabilities
                        (assetID, vulnID, status, discoveredDate, triagedByUserID, dueDate, closedDate, notes)
                     VALUES (:asset, :vuln, :status, :discovered, :triaged, :due, :closed, :notes)'
                );
                $stmt->execute($data);
                $newId = (int)$db->lastInsertId();
                logAction('CREATE', 'asset_vulnerabilities', $newId, 'Mapped vulnerability to asset in Discovered state');
                flash('success', 'Vulnerability mapped to asset successfully.');
            }
            redirect("?page={$entity}/list");
        } catch (PDOException $ex) {
            if ((string)$ex->getCode() === '23000') {
                $errors[] = 'This vulnerability is already mapped to that asset.';
            } else {
                throw $ex;
            }
        }
    }
}

require __DIR__ . '/../../includes/header.php';
?>

<div class="page-header fade-in-up">
    <div>
        <h1 class="h3 mb-1">
            <i class="bi bi-<?= $isEdit ? 'pencil-square' : 'link-45deg' ?> me-2"></i><?= e($pageTitle) ?>
        </h1>
        <p class="text-secondary mb-0"><?= $isEdit ? 'Modify vulnerability lifecycle tracking record' : 'Map a vulnerability to an asset and begin tracking' ?></p>
    </div>
    <a href="?page=asset_vulns/list" class="btn btn-cyber-outline"><i class="bi bi-arrow-left me-1"></i>Back to Board</a>
</div>

<?php if (!empty($errors)): ?>
    <div class="alert alert-danger fade-in-up">
        <i class="bi bi-exclamation-triangle-fill me-2"></i>
        <ul class="mb-0 ps-3">
            <?php foreach ($errors as $err): ?>
                <li><?= e($err) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<div class="glass-card fade-in-up">
    <form method="POST" action="?page=asset_vulns/form<?= $isEdit ? '&id=' . $id : '' ?>">
        <?= csrfField() ?>

        <div class="row g-4">
            <div class="col-md-6">
                <label for="assetID" class="form-label">Asset <span class="text-danger">*</span></label>
                <select class="form-select bg-dark text-light border-secondary" id="assetID" name="assetID" required>
                    <option value="">— Select Asset —</option>
                    <?php $currentAsset = $record['assetID'] ?? ($_POST['assetID'] ?? ''); ?>
                    <?php foreach ($assets as $a): ?>
                        <option value="<?= (int)$a['assetID'] ?>" <?= (string)$currentAsset === (string)$a['assetID'] ? 'selected' : '' ?>><?= e($a['assetName']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="col-md-6">
                <label for="vulnID" class="form-label">Vulnerability <span class="text-danger">*</span></label>
                <select class="form-select bg-dark text-light border-secondary" id="vulnID" name="vulnID" required>
                    <option value="">— Select Vulnerability —</option>
                    <?php $currentVuln = $record['vulnID'] ?? ($_POST['vulnID'] ?? ''); ?>
                    <?php foreach ($vulns as $v): ?>
                        <option value="<?= (int)$v['vulnID'] ?>" <?= (string)$currentVuln === (string)$v['vulnID'] ? 'selected' : '' ?>>
                            <?= e(($v['cveID'] ? $v['cveID'] . ' — ' : '') . $v['title']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="col-md-4">
                <label for="status" class="form-label">Status <span class="text-danger">*</span></label>
                <select class="form-select bg-dark text-light border-secondary" id="status" name="status" required>
                    <?php $currentStatus = $record['status'] ?? ($_POST['status'] ?? 'Discovered'); ?>
                    <?php foreach ($statuses as $st): ?>
                        <option value="<?= e($st) ?>" <?= $currentStatus === $st ? 'selected' : '' ?>><?= e(str_replace('_', ' ', $st)) ?></option>
                    <?php endforeach; ?>
                </select>
                <?php if ($isEdit): ?>
                    <div class="form-text text-secondary small">Transitions are validated server-side.</div>
                <?php endif; ?>
            </div>

            <div class="col-md-4">
                <label for="discoveredDate" class="form-label">Discovered Date <span class="text-danger">*</span></label>
                <input type="date" class="form-control bg-dark text-light border-secondary" id="discoveredDate" name="discoveredDate"
                       value="<?= e($record['discoveredDate'] ?? ($_POST['discoveredDate'] ?? date('Y-m-d'))) ?>" required>
            </div>

            <div class="col-md-4">
                <label for="triagedByUserID" class="form-label">Triaged By</label>
                <select class="form-select bg-dark text-light border-secondary" id="triagedByUserID" name="triagedByUserID">
                    <option value="">— Not Triaged —</option>
                    <?php $currentTriaged = $record['triagedByUserID'] ?? ($_POST['triagedByUserID'] ?? ''); ?>
                    <?php foreach ($users as $u): ?>
                        <option value="<?= (int)$u['userID'] ?>" <?= (string)$currentTriaged === (string)$u['userID'] ? 'selected' : '' ?>><?= e($u['fullName']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="col-md-4">
                <label for="dueDate" class="form-label">Due Date</label>
                <input type="date" class="form-control bg-dark text-light border-secondary" id="dueDate" name="dueDate"
                       value="<?= e($record['dueDate'] ?? ($_POST['dueDate'] ?? '')) ?>">
            </div>

            <div class="col-md-4">
                <label class="form-label">Closed Date</label>
                <input type="text" class="form-control bg-dark text-light border-secondary" value="<?= e($record['closedDate'] ?? 'Open') ?>" readonly>
                <div class="form-text text-secondary small">Set by the server only for Verified Closed or Risk Accepted states.</div>
            </div>

            <div class="col-12">
                <label for="notes" class="form-label">Notes</label>
                <textarea class="form-control bg-dark text-light border-secondary" id="notes" name="notes"
                          rows="4" placeholder="Evidence, triage notes, or risk-acceptance justification..."><?= e($record['notes'] ?? ($_POST['notes'] ?? '')) ?></textarea>
                <div class="form-text text-secondary small">Risk acceptance requires a justification.</div>
            </div>
        </div>

        <hr class="border-secondary my-4">

        <div class="d-flex gap-2">
            <button type="submit" class="btn btn-cyber">
                <i class="bi bi-check-lg me-1"></i><?= $isEdit ? 'Update Record' : 'Create Mapping' ?>
            </button>
            <a href="?page=asset_vulns/list" class="btn btn-cyber-outline">Cancel</a>
        </div>
    </form>
</div>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
