<?php
/**
 * CTVLMS — Findings Create / Edit Form
 */

$pageTitle = 'Finding';
$db        = getDB();
$entity    = 'findings';
$id        = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$isEdit    = $id > 0;

if (!canWrite($entity)) {
    flash('danger', 'Access denied.');
    redirect('?page=findings/list');
}

// ---- Load existing record for edit ----
$record = null;
if ($isEdit) {
    $stmt = $db->prepare('SELECT * FROM findings WHERE findingID = :id');
    $stmt->execute([':id' => $id]);
    $record = $stmt->fetch();
    if (!$record) {
        flash('danger', 'Finding not found.');
        redirect('?page=findings/list');
    }
    $pageTitle = 'Edit Finding';
} else {
    $pageTitle = 'New Finding';
}

// ---- Handle form submission ----
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCSRF();

    $data = [
        'engagementID'         => ($_POST['engagementID'] ?? '') !== '' ? (int)$_POST['engagementID'] : null,
        'assetID'              => ($_POST['assetID'] ?? '') !== '' ? (int)$_POST['assetID'] : null,
        'vulnID'               => ($_POST['vulnID'] ?? '') !== '' ? (int)$_POST['vulnID'] : null,
        'discoveredByUserID'   => ($_POST['discoveredByUserID'] ?? '') !== '' ? (int)$_POST['discoveredByUserID'] : null,
        'title'                => trim($_POST['title'] ?? ''),
        'riskRating'           => $_POST['riskRating'] ?? '',
        'exploitedSuccessfully'=> isset($_POST['exploitedSuccessfully']) ? 1 : 0,
        'proofOfConcept'       => trim($_POST['proofOfConcept'] ?? ''),
        'recommendation'       => trim($_POST['recommendation'] ?? ''),
        'reportedDate'         => $_POST['reportedDate'] ?? null,
    ];

    // Validation
    $errors = [];
    if ($data['title'] === '') {
        $errors[] = 'Title is required.';
    }
    $allowedRisk = ['Critical', 'High', 'Medium', 'Low'];
    if (!in_array($data['riskRating'], $allowedRisk, true)) {
        $errors[] = 'Invalid risk rating.';
    }
    if ($data['engagementID'] === null) {
        $errors[] = 'Engagement is required.';
    }
    if ($data['reportedDate'] === '') $data['reportedDate'] = null;

    if (empty($errors)) {
        if ($isEdit) {
            $stmt = $db->prepare(
                'UPDATE findings SET
                    engagementID = :eid, assetID = :aid, vulnID = :vid,
                    discoveredByUserID = :uid, title = :title, riskRating = :risk,
                    exploitedSuccessfully = :expl, proofOfConcept = :poc,
                    recommendation = :rec, reportedDate = :rd
                 WHERE findingID = :id'
            );
            $stmt->execute([
                ':eid'   => $data['engagementID'],
                ':aid'   => $data['assetID'],
                ':vid'   => $data['vulnID'],
                ':uid'   => $data['discoveredByUserID'],
                ':title' => $data['title'],
                ':risk'  => $data['riskRating'],
                ':expl'  => $data['exploitedSuccessfully'],
                ':poc'   => $data['proofOfConcept'],
                ':rec'   => $data['recommendation'],
                ':rd'    => $data['reportedDate'],
                ':id'    => $id,
            ]);
            logAction('UPDATE', 'findings', $id, 'Updated finding: ' . $data['title']);
        } else {
            $stmt = $db->prepare(
                'INSERT INTO findings
                    (engagementID, assetID, vulnID, discoveredByUserID, title, riskRating,
                     exploitedSuccessfully, proofOfConcept, recommendation, reportedDate)
                 VALUES (:eid, :aid, :vid, :uid, :title, :risk, :expl, :poc, :rec, :rd)'
            );
            $stmt->execute([
                ':eid'   => $data['engagementID'],
                ':aid'   => $data['assetID'],
                ':vid'   => $data['vulnID'],
                ':uid'   => $data['discoveredByUserID'],
                ':title' => $data['title'],
                ':risk'  => $data['riskRating'],
                ':expl'  => $data['exploitedSuccessfully'],
                ':poc'   => $data['proofOfConcept'],
                ':rec'   => $data['recommendation'],
                ':rd'    => $data['reportedDate'],
            ]);
            $id = (int)$db->lastInsertId();
            logAction('INSERT', 'findings', $id, 'Created finding: ' . $data['title']);
        }

        flash('success', 'Finding ' . ($isEdit ? 'updated' : 'created') . ' successfully.');
        redirect('?page=findings/list');
    } else {
        foreach ($errors as $err) {
            flash('danger', $err);
        }
        $record = $data;
        $record['findingID'] = $id;
    }
}

// ---- Load lookup data ----
$engagements    = $db->query('SELECT engagementID, engagementName FROM engagements ORDER BY engagementName')->fetchAll();
$assets         = $db->query('SELECT assetID, assetName FROM assets ORDER BY assetName')->fetchAll();
$vulnerabilities= $db->query('SELECT vulnID, cveID, title FROM vulnerabilities ORDER BY cveID')->fetchAll();
$users          = $db->query('SELECT userID, fullName FROM users WHERE isActive = 1 ORDER BY fullName')->fetchAll();

$riskLevels = ['Critical', 'High', 'Medium', 'Low'];

require __DIR__ . '/../../includes/header.php';
?>

<!-- Page Header -->
<div class="page-header">
    <div>
        <h1 class="h3 mb-0">
            <i class="bi bi-search me-2"></i>
            <?= e($pageTitle) ?>
        </h1>
        <small class="text-muted">
            <a href="?page=findings/list" class="text-decoration-none text-muted">
                <i class="bi bi-arrow-left me-1"></i>Back to Findings
            </a>
        </small>
    </div>
</div>

<!-- Form -->
<div class="glass-card p-4 fade-in-up" style="max-width: 900px;">
    <form method="POST" action="?page=findings/form<?= $isEdit ? '&id=' . $id : '' ?>">
        <?= csrfField() ?>

        <div class="row g-3">
            <!-- Title -->
            <div class="col-12">
                <label for="title" class="form-label">Title <span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="title" name="title"
                       value="<?= e($record['title'] ?? '') ?>" required
                       placeholder="e.g., SQL Injection in Login Form">
            </div>

            <!-- Engagement -->
            <div class="col-md-6">
                <label for="engagementID" class="form-label">Engagement <span class="text-danger">*</span></label>
                <select class="form-select" id="engagementID" name="engagementID" required>
                    <option value="">— Select Engagement —</option>
                    <?php foreach ($engagements as $eng): ?>
                    <option value="<?= (int)$eng['engagementID'] ?>"
                        <?= ((int)($record['engagementID'] ?? 0)) === (int)$eng['engagementID'] ? 'selected' : '' ?>>
                        <?= e($eng['engagementName']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Asset -->
            <div class="col-md-6">
                <label for="assetID" class="form-label">Asset</label>
                <select class="form-select" id="assetID" name="assetID">
                    <option value="">— No specific asset —</option>
                    <?php foreach ($assets as $a): ?>
                    <option value="<?= (int)$a['assetID'] ?>"
                        <?= ((int)($record['assetID'] ?? 0)) === (int)$a['assetID'] ? 'selected' : '' ?>>
                        <?= e($a['assetName']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Linked Vulnerability -->
            <div class="col-md-6">
                <label for="vulnID" class="form-label">Linked Vulnerability</label>
                <select class="form-select" id="vulnID" name="vulnID">
                    <option value="">— Novel Finding (no linked CVE) —</option>
                    <?php foreach ($vulnerabilities as $v): ?>
                    <option value="<?= (int)$v['vulnID'] ?>"
                        <?= ((int)($record['vulnID'] ?? 0)) === (int)$v['vulnID'] ? 'selected' : '' ?>>
                        <?= e($v['cveID']) ?> — <?= e(substr($v['title'], 0, 60)) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
                <small class="text-muted">Leave blank for a novel finding with no known CVE.</small>
            </div>

            <!-- Discovered By -->
            <div class="col-md-6">
                <label for="discoveredByUserID" class="form-label">Discovered By</label>
                <select class="form-select" id="discoveredByUserID" name="discoveredByUserID">
                    <option value="">— Unassigned —</option>
                    <?php foreach ($users as $u): ?>
                    <option value="<?= (int)$u['userID'] ?>"
                        <?= ((int)($record['discoveredByUserID'] ?? 0)) === (int)$u['userID'] ? 'selected' : '' ?>>
                        <?= e($u['fullName']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Risk Rating -->
            <div class="col-md-4">
                <label for="riskRating" class="form-label">Risk Rating <span class="text-danger">*</span></label>
                <select class="form-select" id="riskRating" name="riskRating" required>
                    <option value="">— Select Rating —</option>
                    <?php foreach ($riskLevels as $r): ?>
                    <option value="<?= e($r) ?>"
                        <?= ($record['riskRating'] ?? '') === $r ? 'selected' : '' ?>>
                        <?= e($r) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Reported Date -->
            <div class="col-md-4">
                <label for="reportedDate" class="form-label">Reported Date</label>
                <input type="date" class="form-control" id="reportedDate" name="reportedDate"
                       value="<?= e($record['reportedDate'] ?? date('Y-m-d')) ?>">
            </div>

            <!-- Exploited Successfully -->
            <div class="col-md-4 d-flex align-items-end">
                <div class="form-check form-switch mb-2">
                    <input class="form-check-input" type="checkbox" id="exploitedSuccessfully"
                           name="exploitedSuccessfully" value="1"
                        <?= !empty($record['exploitedSuccessfully']) ? 'checked' : '' ?>>
                    <label class="form-check-label" for="exploitedSuccessfully">
                        Exploited Successfully
                    </label>
                </div>
            </div>

            <!-- Proof of Concept -->
            <div class="col-12">
                <label for="proofOfConcept" class="form-label">Proof of Concept</label>
                <textarea class="form-control font-mono" id="proofOfConcept" name="proofOfConcept"
                          rows="5" placeholder="Steps to reproduce, exploit code, screenshots, etc."><?= e($record['proofOfConcept'] ?? '') ?></textarea>
            </div>

            <!-- Recommendation -->
            <div class="col-12">
                <label for="recommendation" class="form-label">Recommendation</label>
                <textarea class="form-control" id="recommendation" name="recommendation"
                          rows="4" placeholder="Remediation steps, mitigations, compensating controls…"><?= e($record['recommendation'] ?? '') ?></textarea>
            </div>
        </div>

        <!-- Actions -->
        <div class="d-flex justify-content-between align-items-center mt-4 pt-3 border-top border-secondary">
            <a href="?page=findings/list" class="btn btn-outline-secondary">
                <i class="bi bi-x-lg me-1"></i> Cancel
            </a>
            <button type="submit" class="btn btn-cyber">
                <i class="bi bi-check-lg me-1"></i>
                <?= $isEdit ? 'Update Finding' : 'Create Finding' ?>
            </button>
        </div>
    </form>
</div>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
