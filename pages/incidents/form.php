<?php
/**
 * CTVLMS — Incidents: Create / Edit Form
 */

$db = getDB();
$entity = 'incidents';
$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$isEdit = $id > 0;
$pageTitle = $isEdit ? 'Edit Incident' : 'New Incident';

// ---- Access check ----
if (!canWrite($entity)) {
    flash('danger', 'Access denied.');
    redirect('?page=incidents/list');
}

// ---- Handle inline status update (AJAX from list page) ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['inline_status'])) {
    validateCSRF();

    $inlineId     = (int)($_POST['id'] ?? 0);
    $inlineStatus = $_POST['status'] ?? '';
    $validStatuses = ['Open', 'Investigating', 'Contained', 'Eradicated', 'Recovered', 'Closed'];

    if ($inlineId > 0 && in_array($inlineStatus, $validStatuses, true)) {
        // Get old status for audit
        $oldStmt = $db->prepare('SELECT status, closedDate FROM incidents WHERE incidentID = :id');
        $oldStmt->execute([':id' => $inlineId]);
        $oldRecord = $oldStmt->fetch();
        $oldStatus = $oldRecord['status'] ?? '';

        // Auto-set closedDate if status changed to Closed and closedDate is empty
        $closedDate = $oldRecord['closedDate'] ?? null;
        if ($inlineStatus === 'Closed' && empty($closedDate)) {
            $closedDate = date('Y-m-d H:i:s');
        }
        // Clear closedDate if re-opening
        if ($inlineStatus !== 'Closed' && $inlineStatus !== 'Recovered') {
            $closedDate = null;
        }

        $stmt = $db->prepare('UPDATE incidents SET status = :status, closedDate = :closedDate WHERE incidentID = :id');
        $stmt->execute([
            ':status'     => $inlineStatus,
            ':closedDate' => $closedDate,
            ':id'         => $inlineId,
        ]);
        logAction('UPDATE', 'incidents', $inlineId, "Inline status change: {$oldStatus} → {$inlineStatus}");
        http_response_code(200);
        echo 'OK';
    } else {
        http_response_code(400);
        echo 'Invalid request';
    }
    exit;
}

// ---- Load existing record for edit ----
$record = null;
if ($isEdit) {
    $stmt = $db->prepare('SELECT * FROM incidents WHERE incidentID = :id');
    $stmt->execute([':id' => $id]);
    $record = $stmt->fetch();
    if (!$record) {
        flash('danger', 'Incident not found.');
        redirect('?page=incidents/list');
    }
}

// ---- ENUM options ----
$severities = ['Low', 'Medium', 'High', 'Critical'];
$statuses   = ['Open', 'Investigating', 'Contained', 'Eradicated', 'Recovered', 'Closed'];

// ---- Load related data for dropdowns ----
$assets  = $db->query('SELECT assetID, assetName FROM assets ORDER BY assetName ASC')->fetchAll();
$actors  = $db->query('SELECT actorID, actorName FROM threat_actors ORDER BY actorName ASC')->fetchAll();
$vulns   = $db->query('SELECT vulnID, cveID, title FROM vulnerabilities ORDER BY cveID ASC')->fetchAll();
$users   = $db->query("SELECT userID, fullName FROM users WHERE isActive = 1 ORDER BY fullName ASC")->fetchAll();

// ---- Handle form submission ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['inline_status'])) {
    validateCSRF();

    $title            = trim($_POST['title'] ?? '');
    $assetID          = !empty($_POST['assetID']) ? (int)$_POST['assetID'] : null;
    $actorID          = !empty($_POST['actorID']) ? (int)$_POST['actorID'] : null;
    $relatedVulnID    = !empty($_POST['relatedVulnID']) ? (int)$_POST['relatedVulnID'] : null;
    $severity         = $_POST['severity'] ?? '';
    $status           = $_POST['status'] ?? '';
    $detectedDate     = $_POST['detectedDate'] ?? '';
    $closedDate       = $_POST['closedDate'] ?? '';
    $assignedToUserID = !empty($_POST['assignedToUserID']) ? (int)$_POST['assignedToUserID'] : null;
    $description      = trim($_POST['description'] ?? '');

    // Auto-set closedDate on status Closed
    if ($status === 'Closed' && empty($closedDate)) {
        $closedDate = date('Y-m-d\TH:i');
    }

    // Validate
    $errors = [];
    if ($title === '') {
        $errors[] = 'Title is required.';
    }
    if (empty($assetID)) {
        $errors[] = 'Asset is required.';
    }
    if (!in_array($severity, $severities, true)) {
        $errors[] = 'Invalid severity selected.';
    }
    if (!in_array($status, $statuses, true)) {
        $errors[] = 'Invalid status selected.';
    }

    if (!empty($errors)) {
        foreach ($errors as $err) {
            flash('danger', $err);
        }
    } else {
        // Format dates for DB
        $detectedDateDb = !empty($detectedDate) ? date('Y-m-d H:i:s', strtotime($detectedDate)) : null;
        $closedDateDb   = !empty($closedDate) ? date('Y-m-d H:i:s', strtotime($closedDate)) : null;

        if ($isEdit) {
            // Get old status for audit detail
            $oldStatus = $record['status'];
            $statusDetail = '';
            if ($oldStatus !== $status) {
                $statusDetail = " | Status: {$oldStatus} → {$status}";
            }

            $stmt = $db->prepare(
                'UPDATE incidents
                    SET title = :title,
                        assetID = :assetID,
                        actorID = :actorID,
                        relatedVulnID = :relatedVulnID,
                        severity = :severity,
                        status = :status,
                        detectedDate = :detectedDate,
                        closedDate = :closedDate,
                        assignedToUserID = :assignedToUserID,
                        description = :description
                  WHERE incidentID = :id'
            );
            $stmt->execute([
                ':title'            => $title,
                ':assetID'          => $assetID,
                ':actorID'          => $actorID,
                ':relatedVulnID'    => $relatedVulnID,
                ':severity'         => $severity,
                ':status'           => $status,
                ':detectedDate'     => $detectedDateDb,
                ':closedDate'       => $closedDateDb,
                ':assignedToUserID' => $assignedToUserID,
                ':description'      => $description ?: null,
                ':id'               => $id,
            ]);
            logAction('UPDATE', 'incidents', $id, "Updated incident: {$title}{$statusDetail}");
            flash('success', 'Incident updated successfully.');
        } else {
            $stmt = $db->prepare(
                'INSERT INTO incidents
                    (title, assetID, actorID, relatedVulnID, severity, status, detectedDate, closedDate, assignedToUserID, description)
                 VALUES (:title, :assetID, :actorID, :relatedVulnID, :severity, :status, :detectedDate, :closedDate, :assignedToUserID, :description)'
            );
            $stmt->execute([
                ':title'            => $title,
                ':assetID'          => $assetID,
                ':actorID'          => $actorID,
                ':relatedVulnID'    => $relatedVulnID,
                ':severity'         => $severity,
                ':status'           => $status,
                ':detectedDate'     => $detectedDateDb,
                ':closedDate'       => $closedDateDb,
                ':assignedToUserID' => $assignedToUserID,
                ':description'      => $description ?: null,
            ]);
            $newId = (int)$db->lastInsertId();
            logAction('INSERT', 'incidents', $newId, "Created incident: {$title} [{$severity} / {$status}]");
            flash('success', 'Incident created successfully.');
        }
        redirect('?page=incidents/list');
    }
}

// ---- Populate form values ----
$f = [
    'title'            => $_POST['title']            ?? ($record['title'] ?? ''),
    'assetID'          => $_POST['assetID']          ?? ($record['assetID'] ?? ''),
    'actorID'          => $_POST['actorID']          ?? ($record['actorID'] ?? ''),
    'relatedVulnID'    => $_POST['relatedVulnID']    ?? ($record['relatedVulnID'] ?? ''),
    'severity'         => $_POST['severity']         ?? ($record['severity'] ?? 'Medium'),
    'status'           => $_POST['status']           ?? ($record['status'] ?? 'Open'),
    'detectedDate'     => $_POST['detectedDate']     ?? ($record['detectedDate'] ?? ''),
    'closedDate'       => $_POST['closedDate']       ?? ($record['closedDate'] ?? ''),
    'assignedToUserID' => $_POST['assignedToUserID'] ?? ($record['assignedToUserID'] ?? ''),
    'description'      => $_POST['description']      ?? ($record['description'] ?? ''),
];

// Format datetime-local values
$detectedVal = !empty($f['detectedDate']) ? date('Y-m-d\TH:i', strtotime($f['detectedDate'])) : '';
$closedVal   = !empty($f['closedDate'])   ? date('Y-m-d\TH:i', strtotime($f['closedDate']))   : '';

require __DIR__ . '/../../includes/header.php';
?>

<!-- Page Header -->
<div class="page-header">
    <div>
        <h1 class="h3 mb-0">
            <i class="bi bi-exclamation-triangle me-2"></i><?= e($pageTitle) ?>
        </h1>
        <small class="text-muted">
            <?= $isEdit ? 'Editing: ' . e($record['title']) : 'Log a new security incident' ?>
        </small>
    </div>
    <a href="?page=incidents/list" class="btn btn-cyber-outline">
        <i class="bi bi-arrow-left me-1"></i> Back to List
    </a>
</div>

<!-- Form -->
<div class="glass-card fade-in-up" style="max-width:850px;">
    <form method="POST" action="?page=incidents/form<?= $isEdit ? '&id=' . $id : '' ?>" id="incidentForm">
        <?= csrfField() ?>

        <!-- Title -->
        <div class="mb-3">
            <label for="title" class="form-label">Title <span class="text-danger">*</span></label>
            <input type="text" class="form-control" id="title" name="title"
                   value="<?= e($f['title']) ?>" required maxlength="200"
                   placeholder="e.g. Ransomware detected on web server">
        </div>

        <div class="row g-3">
            <!-- Asset -->
            <div class="col-md-6 mb-3">
                <label for="assetID" class="form-label">Affected Asset <span class="text-danger">*</span></label>
                <select class="form-select" id="assetID" name="assetID" required>
                    <option value="">— Select Asset —</option>
                    <?php foreach ($assets as $a): ?>
                    <option value="<?= (int)$a['assetID'] ?>" <?= (int)$f['assetID'] === (int)$a['assetID'] && $f['assetID'] !== '' ? 'selected' : '' ?>>
                        <?= e($a['assetName']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Assigned To -->
            <div class="col-md-6 mb-3">
                <label for="assignedToUserID" class="form-label">Assigned To</label>
                <select class="form-select" id="assignedToUserID" name="assignedToUserID">
                    <option value="">— Unassigned —</option>
                    <?php foreach ($users as $u): ?>
                    <option value="<?= (int)$u['userID'] ?>" <?= (int)$f['assignedToUserID'] === (int)$u['userID'] && $f['assignedToUserID'] !== '' ? 'selected' : '' ?>>
                        <?= e($u['fullName']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>
        </div>

        <div class="row g-3">
            <!-- Threat Actor -->
            <div class="col-md-6 mb-3">
                <label for="actorID" class="form-label">Threat Actor</label>
                <select class="form-select" id="actorID" name="actorID">
                    <option value="">— Unknown / N/A —</option>
                    <?php foreach ($actors as $a): ?>
                    <option value="<?= (int)$a['actorID'] ?>" <?= (int)$f['actorID'] === (int)$a['actorID'] && $f['actorID'] !== '' ? 'selected' : '' ?>>
                        <?= e($a['actorName']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
                <div class="form-text">Optional — attribute incident to a known threat actor.</div>
            </div>

            <!-- Related Vulnerability -->
            <div class="col-md-6 mb-3">
                <label for="relatedVulnID" class="form-label">Related Vulnerability</label>
                <select class="form-select" id="relatedVulnID" name="relatedVulnID">
                    <option value="">— None —</option>
                    <?php foreach ($vulns as $v): ?>
                    <option value="<?= (int)$v['vulnID'] ?>" <?= (int)$f['relatedVulnID'] === (int)$v['vulnID'] && $f['relatedVulnID'] !== '' ? 'selected' : '' ?>>
                        <?= e($v['cveID'] . ' — ' . mb_substr($v['title'], 0, 50)) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
                <div class="form-text">Optional — link to an exploited vulnerability.</div>
            </div>
        </div>

        <div class="row g-3">
            <!-- Severity -->
            <div class="col-md-6 mb-3">
                <label for="severity" class="form-label">Severity <span class="text-danger">*</span></label>
                <select class="form-select" id="severity" name="severity" required>
                    <?php foreach ($severities as $s): ?>
                    <option value="<?= e($s) ?>" <?= $f['severity'] === $s ? 'selected' : '' ?>>
                        <?= e($s) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Status -->
            <div class="col-md-6 mb-3">
                <label for="status" class="form-label">Status <span class="text-danger">*</span></label>
                <select class="form-select" id="status" name="status" required onchange="handleStatusChange(this)">
                    <?php foreach ($statuses as $st): ?>
                    <option value="<?= e($st) ?>" <?= $f['status'] === $st ? 'selected' : '' ?>>
                        <?= e(str_replace('_', ' ', $st)) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>
        </div>

        <div class="row g-3">
            <!-- Detected Date -->
            <div class="col-md-6 mb-3">
                <label for="detectedDate" class="form-label">Detected Date</label>
                <input type="datetime-local" class="form-control" id="detectedDate" name="detectedDate"
                       value="<?= e($detectedVal) ?>">
            </div>

            <!-- Closed Date -->
            <div class="col-md-6 mb-3">
                <label for="closedDate" class="form-label">Closed Date</label>
                <input type="datetime-local" class="form-control" id="closedDate" name="closedDate"
                       value="<?= e($closedVal) ?>">
                <div class="form-text">Auto-filled when status is set to Closed.</div>
            </div>
        </div>

        <!-- Description -->
        <div class="mb-4">
            <label for="description" class="form-label">Description</label>
            <textarea class="form-control" id="description" name="description" rows="5"
                      placeholder="Describe the incident, timeline, impact, and response actions..."><?= e($f['description']) ?></textarea>
        </div>

        <!-- Submit -->
        <div class="d-flex gap-2">
            <button type="submit" class="btn btn-cyber">
                <i class="bi bi-check-lg me-1"></i> <?= $isEdit ? 'Update Incident' : 'Log Incident' ?>
            </button>
            <a href="?page=incidents/list" class="btn btn-cyber-outline">Cancel</a>
        </div>
    </form>
</div>

<script>
/**
 * Auto-set closedDate when status is changed to Closed.
 */
function handleStatusChange(select) {
    const closedInput = document.getElementById('closedDate');
    if (select.value === 'Closed' && !closedInput.value) {
        // Set to current local datetime
        const now = new Date();
        const pad = n => n.toString().padStart(2, '0');
        const formatted = now.getFullYear() + '-' + pad(now.getMonth() + 1) + '-' + pad(now.getDate())
                        + 'T' + pad(now.getHours()) + ':' + pad(now.getMinutes());
        closedInput.value = formatted;
    }
}
</script>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
