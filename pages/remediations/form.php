<?php
$pageTitle = 'Create/Edit Remediation';
$db = getDB();
$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$isEdit = $id > 0;
$entity = 'remediations';

if (!canWrite($entity)) {
    flash('danger', 'Access denied.');
    redirect("?page={$entity}/list");
}

$record = null;
if ($isEdit) {
    $stmt = $db->prepare('SELECT * FROM remediations WHERE remediationID = :id');
    $stmt->execute([':id' => $id]);
    $record = $stmt->fetch();
    if (!$record) {
        flash('danger', 'Record not found.');
        redirect("?page={$entity}/list");
    }
}

$assetVulns = $db->query(
    'SELECT av.assetVulnID, av.status, a.assetName, v.title AS vulnTitle
     FROM asset_vulnerabilities av
     JOIN assets a ON av.assetID = a.assetID
     JOIN vulnerabilities v ON av.vulnID = v.vulnID
     ORDER BY a.assetName, v.title'
)->fetchAll();

$users = $db->query('SELECT userID, fullName FROM users WHERE isActive = 1 ORDER BY fullName')->fetchAll();

// Verification is an authenticated action. The verifier identity and date are
// always set by the server and can never be supplied by the browser.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify_remediation'])) {
    validateCSRF();

    if (!$isEdit || !canVerifyRemediation()) {
        http_response_code(403);
        flash('danger', 'Only Admins or Vulnerability Managers can verify remediation.');
        redirect("?page={$entity}/list");
    }

    if (empty($record['completedDate'])) {
        flash('danger', 'A remediation must be completed before it can be verified.');
        redirect("?page={$entity}/form&id={$id}");
    }

    $verifierID = (int)($_SESSION['user_id'] ?? 0);
    if ($verifierID <= 0) {
        http_response_code(403);
        exit('Authenticated verifier required.');
    }

    $db->beginTransaction();
    try {
        $stmt = $db->prepare(
            'UPDATE remediations
             SET verifiedByUserID = :uid, verificationDate = :vd
             WHERE remediationID = :id'
        );
        $stmt->execute([':uid' => $verifierID, ':vd' => date('Y-m-d'), ':id' => $id]);
        logAction('VERIFY', 'remediations', $id, 'Remediation verified by authenticated user');

        $avStmt = $db->prepare('SELECT status FROM asset_vulnerabilities WHERE assetVulnID = :id FOR UPDATE');
        $avStmt->execute([':id' => (int)$record['assetVulnID']]);
        $av = $avStmt->fetch();

        if ($av && $av['status'] === 'Remediated') {
            // The verification record now exists, so Verified_Closed is valid.
            $error = validateLifecycleTransition(
                $db,
                (int)$record['assetVulnID'],
                'Remediated',
                'Verified_Closed'
            );
            if ($error === null) {
                $close = $db->prepare(
                    'UPDATE asset_vulnerabilities
                     SET status = :status, closedDate = :closed
                     WHERE assetVulnID = :id'
                );
                $close->execute([
                    ':status' => 'Verified_Closed',
                    ':closed' => date('Y-m-d'),
                    ':id' => (int)$record['assetVulnID'],
                ]);
                logAction(
                    'STATUS_CHANGE',
                    'asset_vulnerabilities',
                    (int)$record['assetVulnID'],
                    'Status: Remediated → Verified_Closed after remediation verification'
                );
            }
        }

        $db->commit();
        flash('success', 'Remediation verified successfully.');
    } catch (Throwable $ex) {
        if ($db->inTransaction()) $db->rollBack();
        throw $ex;
    }

    redirect("?page={$entity}/form&id={$id}");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['verify_remediation'])) {
    validateCSRF();

    $assetVulnID = (int)($_POST['assetVulnID'] ?? 0);
    $assignedToUserID = !empty($_POST['assignedToUserID']) ? (int)$_POST['assignedToUserID'] : null;
    $actionTaken = trim($_POST['actionTaken'] ?? '');
    $remediationType = $_POST['remediationType'] ?? '';
    $startedDate = !empty($_POST['startedDate']) ? $_POST['startedDate'] : null;
    $completedDate = !empty($_POST['completedDate']) ? $_POST['completedDate'] : null;

    $validTypes = ['Patch', 'Configuration_Change', 'Compensating_Control', 'Decommission', 'Risk_Acceptance'];
    $errors = [];
    if ($assetVulnID <= 0) $errors[] = 'Target asset and vulnerability are required.';
    if ($actionTaken === '') $errors[] = 'Action taken is required.';
    if (!in_array($remediationType, $validTypes, true)) $errors[] = 'Invalid remediation type.';
    if ($completedDate !== null && $startedDate !== null && $completedDate < $startedDate) {
        $errors[] = 'Completed date cannot be before started date.';
    }

    if (empty($errors)) {
        $db->beginTransaction();
        try {
            if ($isEdit) {
                $materialChanged =
                    (int)$record['assetVulnID'] !== $assetVulnID ||
                    (string)$record['actionTaken'] !== $actionTaken ||
                    (string)$record['remediationType'] !== $remediationType ||
                    (string)($record['completedDate'] ?? '') !== (string)($completedDate ?? '');

                $sql = 'UPDATE remediations SET
                            assetVulnID = :assetVulnID,
                            assignedToUserID = :assignedToUserID,
                            actionTaken = :actionTaken,
                            remediationType = :remediationType,
                            startedDate = :startedDate,
                            completedDate = :completedDate';
                if ($materialChanged) {
                    $sql .= ', verifiedByUserID = NULL, verificationDate = NULL';
                }
                $sql .= ' WHERE remediationID = :id';

                $stmt = $db->prepare($sql);
                $stmt->execute([
                    ':assetVulnID' => $assetVulnID,
                    ':assignedToUserID' => $assignedToUserID,
                    ':actionTaken' => $actionTaken,
                    ':remediationType' => $remediationType,
                    ':startedDate' => $startedDate,
                    ':completedDate' => $completedDate,
                    ':id' => $id,
                ]);
                logAction('UPDATE', 'remediations', $id, $materialChanged
                    ? 'Updated remediation record; previous verification invalidated'
                    : 'Updated remediation record');
                flash('success', 'Remediation updated successfully.');
            } else {
                $stmt = $db->prepare(
                    'INSERT INTO remediations
                        (assetVulnID, assignedToUserID, actionTaken, remediationType, startedDate, completedDate)
                     VALUES (:assetVulnID, :assignedToUserID, :actionTaken, :remediationType, :startedDate, :completedDate)'
                );
                $stmt->execute([
                    ':assetVulnID' => $assetVulnID,
                    ':assignedToUserID' => $assignedToUserID,
                    ':actionTaken' => $actionTaken,
                    ':remediationType' => $remediationType,
                    ':startedDate' => $startedDate,
                    ':completedDate' => $completedDate,
                ]);
                $id = (int)$db->lastInsertId();
                logAction('CREATE', 'remediations', $id, 'Created remediation record');
                flash('success', 'Remediation created successfully.');
            }

            $db->commit();
        } catch (Throwable $ex) {
            if ($db->inTransaction()) $db->rollBack();
            throw $ex;
        }

        redirect("?page={$entity}/form&id={$id}");
    }

    foreach ($errors as $error) flash('danger', $error);
}

// Reload after any successful write.
if ($id > 0) {
    $stmt = $db->prepare(
        'SELECT r.*, vu.fullName AS verifierName
         FROM remediations r
         LEFT JOIN users vu ON r.verifiedByUserID = vu.userID
         WHERE r.remediationID = :id'
    );
    $stmt->execute([':id' => $id]);
    $record = $stmt->fetch() ?: $record;
}

require __DIR__ . '/../../includes/header.php';
?>

<div class="page-header fade-in-up">
    <h2><i class="bi bi-wrench"></i> <?= $isEdit ? 'Edit Remediation' : 'Log Remediation Action' ?></h2>
    <a href="?page=remediations/list" class="btn btn-cyber-outline"><i class="bi bi-arrow-left"></i> Back to Remediations</a>
</div>

<div class="glass-card fade-in-up" style="animation-delay: 0.1s;">
    <div class="card-body p-4">
        <form method="POST" action="?page=remediations/form<?= $id ? '&id=' . $id : '' ?>">
            <?= csrfField() ?>

            <div class="row mb-3">
                <div class="col-md-8">
                    <label class="form-label">Target Asset & Vulnerability <span class="text-danger">*</span></label>
                    <select name="assetVulnID" class="form-select" required>
                        <option value="">-- Select Target --</option>
                        <?php foreach ($assetVulns as $av): ?>
                            <option value="<?= (int)$av['assetVulnID'] ?>" <?= (string)($record['assetVulnID'] ?? '') === (string)$av['assetVulnID'] ? 'selected' : '' ?>>
                                <?= e($av['assetName']) ?> — <?= e($av['vulnTitle']) ?> [<?= e(str_replace('_', ' ', $av['status'])) ?>]
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-4">
                    <label class="form-label">Remediation Type <span class="text-danger">*</span></label>
                    <select name="remediationType" class="form-select" required>
                        <option value="">-- Select Type --</option>
                        <?php foreach (['Patch', 'Configuration_Change', 'Compensating_Control', 'Decommission', 'Risk_Acceptance'] as $t): ?>
                            <option value="<?= e($t) ?>" <?= ($record['remediationType'] ?? '') === $t ? 'selected' : '' ?>><?= e(str_replace('_', ' ', $t)) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </div>

            <div class="mb-3">
                <label class="form-label">Action Taken / Details <span class="text-danger">*</span></label>
                <textarea name="actionTaken" class="form-control" rows="4" required><?= e($record['actionTaken'] ?? '') ?></textarea>
            </div>

            <div class="row mb-4">
                <div class="col-md-6">
                    <label class="form-label">Assigned To</label>
                    <select name="assignedToUserID" class="form-select">
                        <option value="">-- Unassigned --</option>
                        <?php foreach ($users as $u): ?>
                            <option value="<?= (int)$u['userID'] ?>" <?= (string)($record['assignedToUserID'] ?? '') === (string)$u['userID'] ? 'selected' : '' ?>><?= e($u['fullName']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-3">
                    <label class="form-label">Started Date</label>
                    <input type="date" name="startedDate" class="form-control" value="<?= e($record['startedDate'] ?? '') ?>">
                </div>
                <div class="col-md-3">
                    <label class="form-label">Completed Date</label>
                    <input type="date" name="completedDate" class="form-control" value="<?= e($record['completedDate'] ?? '') ?>">
                </div>
            </div>

            <div class="d-flex justify-content-end gap-2">
                <a href="?page=remediations/list" class="btn btn-secondary">Back</a>
                <button type="submit" class="btn btn-cyber"><i class="bi bi-save"></i> Save Remediation</button>
            </div>
        </form>
    </div>
</div>

<?php if ($id > 0): ?>
<div class="glass-card fade-in-up mt-4">
    <div class="card-body p-4">
        <h5><i class="bi bi-patch-check me-2"></i>Verification</h5>
        <?php if (!empty($record['verifiedByUserID'])): ?>
            <div class="alert alert-success mb-0">
                Verified by <strong><?= e($record['verifierName'] ?? ('User #' . $record['verifiedByUserID'])) ?></strong>
                on <?= e($record['verificationDate']) ?>.
            </div>
        <?php elseif (empty($record['completedDate'])): ?>
            <div class="alert alert-secondary mb-0">Mark the remediation completed before verification.</div>
        <?php elseif (canVerifyRemediation()): ?>
            <p class="text-secondary">Verification records your authenticated identity and may automatically close a Remediated exposure.</p>
            <form method="POST" action="?page=remediations/form&id=<?= (int)$id ?>">
                <?= csrfField() ?>
                <input type="hidden" name="verify_remediation" value="1">
                <button type="submit" class="btn btn-success" onclick="return confirm('Verify this remediation as effective?');">
                    <i class="bi bi-shield-check me-1"></i>Verify Remediation
                </button>
            </form>
        <?php else: ?>
            <div class="alert alert-warning mb-0">Verification requires an Admin or Vulnerability Manager.</div>
        <?php endif; ?>
    </div>
</div>
<?php endif; ?>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
