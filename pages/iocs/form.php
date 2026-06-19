<?php
/**
 * CTVLMS — Indicators of Compromise: Create / Edit Form
 */

$db = getDB();
$entity = 'iocs';
$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$isEdit = $id > 0;
$pageTitle = $isEdit ? 'Edit IOC' : 'New IOC';

// ---- Access check ----
if (!canWrite($entity)) {
    flash('danger', 'Access denied.');
    redirect('?page=iocs/list');
}

// ---- Load existing record for edit ----
$record = null;
if ($isEdit) {
    $stmt = $db->prepare('SELECT * FROM indicators_of_compromise WHERE iocID = :id');
    $stmt->execute([':id' => $id]);
    $record = $stmt->fetch();
    if (!$record) {
        flash('danger', 'IOC not found.');
        redirect('?page=iocs/list');
    }
}

// ---- ENUM options ----
$iocTypes         = ['IP', 'Domain', 'URL', 'File_Hash', 'Email', 'Registry_Key'];
$confidenceLevels = ['Low', 'Medium', 'High'];

// ---- Load threat actors for dropdown ----
$actors = $db->query('SELECT actorID, actorName FROM threat_actors ORDER BY actorName ASC')->fetchAll();

// ---- Handle form submission ----
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCSRF();

    $actorID         = !empty($_POST['actorID']) ? (int)$_POST['actorID'] : null;
    $iocType         = $_POST['iocType'] ?? '';
    $iocValue        = trim($_POST['iocValue'] ?? '');
    $mitreTechnique  = trim($_POST['mitreTechnique'] ?? '');
    $firstSeen       = $_POST['firstSeen'] ?? '';
    $lastSeen        = $_POST['lastSeen'] ?? '';
    $confidenceLevel = $_POST['confidenceLevel'] ?? '';

    // Validate
    $errors = [];
    if ($iocValue === '') {
        $errors[] = 'IOC value is required.';
    }
    if (!in_array($iocType, $iocTypes, true)) {
        $errors[] = 'Invalid IOC type selected.';
    }
    if (!in_array($confidenceLevel, $confidenceLevels, true)) {
        $errors[] = 'Invalid confidence level selected.';
    }

    if (!empty($errors)) {
        foreach ($errors as $err) {
            flash('danger', $err);
        }
    } else {
        if ($isEdit) {
            $stmt = $db->prepare(
                'UPDATE indicators_of_compromise
                    SET actorID = :actorID,
                        iocType = :iocType,
                        iocValue = :iocValue,
                        mitreTechnique = :mitreTechnique,
                        firstSeen = :firstSeen,
                        lastSeen = :lastSeen,
                        confidenceLevel = :confidenceLevel
                  WHERE iocID = :id'
            );
            $stmt->execute([
                ':actorID'         => $actorID,
                ':iocType'         => $iocType,
                ':iocValue'        => $iocValue,
                ':mitreTechnique'  => $mitreTechnique ?: null,
                ':firstSeen'       => $firstSeen ?: null,
                ':lastSeen'        => $lastSeen ?: null,
                ':confidenceLevel' => $confidenceLevel,
                ':id'              => $id,
            ]);
            logAction('UPDATE', 'indicators_of_compromise', $id, "Updated IOC: {$iocValue} ({$iocType})");
            flash('success', 'IOC updated successfully.');
        } else {
            $stmt = $db->prepare(
                'INSERT INTO indicators_of_compromise
                    (actorID, iocType, iocValue, mitreTechnique, firstSeen, lastSeen, confidenceLevel)
                 VALUES (:actorID, :iocType, :iocValue, :mitreTechnique, :firstSeen, :lastSeen, :confidenceLevel)'
            );
            $stmt->execute([
                ':actorID'         => $actorID,
                ':iocType'         => $iocType,
                ':iocValue'        => $iocValue,
                ':mitreTechnique'  => $mitreTechnique ?: null,
                ':firstSeen'       => $firstSeen ?: null,
                ':lastSeen'        => $lastSeen ?: null,
                ':confidenceLevel' => $confidenceLevel,
            ]);
            $newId = (int)$db->lastInsertId();
            logAction('INSERT', 'indicators_of_compromise', $newId, "Created IOC: {$iocValue} ({$iocType})");
            flash('success', 'IOC created successfully.');
        }
        redirect('?page=iocs/list');
    }
}

// ---- Populate form values ----
$f = [
    'actorID'         => $_POST['actorID']         ?? ($record['actorID'] ?? ''),
    'iocType'         => $_POST['iocType']         ?? ($record['iocType'] ?? ''),
    'iocValue'        => $_POST['iocValue']        ?? ($record['iocValue'] ?? ''),
    'mitreTechnique'  => $_POST['mitreTechnique']  ?? ($record['mitreTechnique'] ?? ''),
    'firstSeen'       => $_POST['firstSeen']       ?? ($record['firstSeen'] ?? ''),
    'lastSeen'        => $_POST['lastSeen']        ?? ($record['lastSeen'] ?? ''),
    'confidenceLevel' => $_POST['confidenceLevel'] ?? ($record['confidenceLevel'] ?? 'Medium'),
];

require __DIR__ . '/../../includes/header.php';
?>

<!-- Page Header -->
<div class="page-header">
    <div>
        <h1 class="h3 mb-0">
            <i class="bi bi-fingerprint me-2"></i><?= e($pageTitle) ?>
        </h1>
        <small class="text-muted">
            <?= $isEdit ? 'Editing: ' . e($record['iocValue']) : 'Register a new indicator of compromise' ?>
        </small>
    </div>
    <a href="?page=iocs/list" class="btn btn-cyber-outline">
        <i class="bi bi-arrow-left me-1"></i> Back to List
    </a>
</div>

<!-- Form -->
<div class="glass-card fade-in-up" style="max-width:750px;">
    <form method="POST" action="?page=iocs/form<?= $isEdit ? '&id=' . $id : '' ?>">
        <?= csrfField() ?>

        <div class="row g-3">
            <!-- IOC Type -->
            <div class="col-md-4 mb-3">
                <label for="iocType" class="form-label">IOC Type <span class="text-danger">*</span></label>
                <select class="form-select" id="iocType" name="iocType" required>
                    <option value="">— Select Type —</option>
                    <?php foreach ($iocTypes as $t): ?>
                    <option value="<?= e($t) ?>" <?= $f['iocType'] === $t ? 'selected' : '' ?>>
                        <?= e(str_replace('_', ' ', $t)) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- IOC Value -->
            <div class="col-md-8 mb-3">
                <label for="iocValue" class="form-label">IOC Value <span class="text-danger">*</span></label>
                <input type="text" class="form-control font-mono" id="iocValue" name="iocValue"
                       value="<?= e($f['iocValue']) ?>" required maxlength="500"
                       placeholder="e.g. 192.168.1.100, evil.com, d41d8cd98f...">
            </div>
        </div>

        <div class="row g-3">
            <!-- Linked Threat Actor -->
            <div class="col-md-6 mb-3">
                <label for="actorID" class="form-label">Linked Threat Actor</label>
                <select class="form-select" id="actorID" name="actorID">
                    <option value="">— Unattributed —</option>
                    <?php foreach ($actors as $a): ?>
                    <option value="<?= (int)$a['actorID'] ?>" <?= (int)$f['actorID'] === (int)$a['actorID'] && $f['actorID'] !== '' ? 'selected' : '' ?>>
                        <?= e($a['actorName']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
                <div class="form-text">Optional — link this IOC to a known threat actor.</div>
            </div>

            <!-- Confidence Level -->
            <div class="col-md-6 mb-3">
                <label for="confidenceLevel" class="form-label">Confidence Level <span class="text-danger">*</span></label>
                <select class="form-select" id="confidenceLevel" name="confidenceLevel" required>
                    <?php foreach ($confidenceLevels as $c): ?>
                    <option value="<?= e($c) ?>" <?= $f['confidenceLevel'] === $c ? 'selected' : '' ?>>
                        <?= e($c) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>
        </div>

        <!-- MITRE Technique -->
        <div class="mb-3">
            <label for="mitreTechnique" class="form-label">MITRE ATT&CK Technique</label>
            <input type="text" class="form-control font-mono" id="mitreTechnique" name="mitreTechnique"
                   value="<?= e($f['mitreTechnique']) ?>" maxlength="100"
                   placeholder="e.g. T1566.001, T1059.001">
            <div class="form-text">Optional — MITRE ATT&CK technique ID (e.g. T1566.001).</div>
        </div>

        <div class="row g-3">
            <!-- First Seen -->
            <div class="col-md-6 mb-3">
                <label for="firstSeen" class="form-label">First Seen</label>
                <input type="date" class="form-control" id="firstSeen" name="firstSeen"
                       value="<?= e($f['firstSeen'] ? date('Y-m-d', strtotime($f['firstSeen'])) : '') ?>">
            </div>

            <!-- Last Seen -->
            <div class="col-md-6 mb-3">
                <label for="lastSeen" class="form-label">Last Seen</label>
                <input type="date" class="form-control" id="lastSeen" name="lastSeen"
                       value="<?= e($f['lastSeen'] ? date('Y-m-d', strtotime($f['lastSeen'])) : '') ?>">
            </div>
        </div>

        <!-- Submit -->
        <div class="d-flex gap-2 mt-2">
            <button type="submit" class="btn btn-cyber">
                <i class="bi bi-check-lg me-1"></i> <?= $isEdit ? 'Update IOC' : 'Create IOC' ?>
            </button>
            <a href="?page=iocs/list" class="btn btn-cyber-outline">Cancel</a>
        </div>
    </form>
</div>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
