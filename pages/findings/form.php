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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCSRF();

    $data = [
        'engagementID'          => ($_POST['engagementID'] ?? '') !== '' ? (int)$_POST['engagementID'] : null,
        'assetID'               => ($_POST['assetID'] ?? '') !== '' ? (int)$_POST['assetID'] : null,
        'vulnID'                => ($_POST['vulnID'] ?? '') !== '' ? (int)$_POST['vulnID'] : null,
        'discoveredByUserID'    => ($_POST['discoveredByUserID'] ?? '') !== '' ? (int)$_POST['discoveredByUserID'] : null,
        'title'                 => trim($_POST['title'] ?? ''),
        'riskRating'            => $_POST['riskRating'] ?? '',
        'exploitedSuccessfully' => isset($_POST['exploitedSuccessfully']) ? 1 : 0,
        'proofOfConcept'        => trim($_POST['proofOfConcept'] ?? ''),
        'recommendation'        => trim($_POST['recommendation'] ?? ''),
        'reportedDate'          => $_POST['reportedDate'] ?? null,
    ];

    $errors = [];
    if ($data['title'] === '') $errors[] = 'Title is required.';
    if (!in_array($data['riskRating'], ['Critical', 'High', 'Medium', 'Low'], true)) {
        $errors[] = 'Invalid risk rating.';
    }
    if ($data['engagementID'] === null) $errors[] = 'Engagement is required.';
    if ($data['assetID'] === null) $errors[] = 'An in-scope asset is required.';
    if ($data['reportedDate'] === '') $data['reportedDate'] = null;

    // A red-team/pentest finding may only target an asset explicitly scoped into
    // the selected engagement. This is enforced server-side; the dropdown is
    // only a convenience and is not trusted as an authorization boundary.
    if ($data['engagementID'] !== null && $data['assetID'] !== null) {
        $scopeStmt = $db->prepare(
            'SELECT 1
             FROM engagement_assets
             WHERE engagementID = :eid AND assetID = :aid
             LIMIT 1'
        );
        $scopeStmt->execute([
            ':eid' => $data['engagementID'],
            ':aid' => $data['assetID'],
        ]);
        if (!$scopeStmt->fetchColumn()) {
            $errors[] = 'The selected asset is outside this engagement scope.';
        }
    }

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
            logAction('UPDATE', 'findings', $id, 'Updated in-scope finding: ' . $data['title']);
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
            logAction('CREATE', 'findings', $id, 'Created in-scope finding: ' . $data['title']);
        }

        flash('success', 'Finding ' . ($isEdit ? 'updated' : 'created') . ' successfully.');
        redirect('?page=findings/list');
    }

    foreach ($errors as $err) flash('danger', $err);
    $record = $data;
    $record['findingID'] = $id;
}

$engagements = $db->query('SELECT engagementID, engagementName FROM engagements ORDER BY engagementName')->fetchAll();

// Include scope membership for client-side filtering while retaining backend enforcement.
$assetRows = $db->query(
    'SELECT a.assetID, a.assetName, ea.engagementID
     FROM assets a
     JOIN engagement_assets ea ON ea.assetID = a.assetID
     ORDER BY a.assetName'
)->fetchAll();
$assetsByEngagement = [];
foreach ($assetRows as $row) {
    $assetsByEngagement[(int)$row['engagementID']][] = [
        'assetID' => (int)$row['assetID'],
        'assetName' => $row['assetName'],
    ];
}

$vulnerabilities = $db->query('SELECT vulnID, cveID, title FROM vulnerabilities ORDER BY cveID')->fetchAll();
$users = $db->query('SELECT userID, fullName FROM users WHERE isActive = 1 ORDER BY fullName')->fetchAll();
$riskLevels = ['Critical', 'High', 'Medium', 'Low'];

require __DIR__ . '/../../includes/header.php';
?>

<div class="page-header">
    <div>
        <h1 class="h3 mb-0"><i class="bi bi-search me-2"></i><?= e($pageTitle) ?></h1>
        <small class="text-muted">
            <a href="?page=findings/list" class="text-decoration-none text-muted"><i class="bi bi-arrow-left me-1"></i>Back to Findings</a>
        </small>
    </div>
</div>

<div class="glass-card p-4 fade-in-up" style="max-width: 900px;">
    <form method="POST" action="?page=findings/form<?= $isEdit ? '&id=' . $id : '' ?>">
        <?= csrfField() ?>

        <div class="row g-3">
            <div class="col-12">
                <label for="title" class="form-label">Title <span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="title" name="title" value="<?= e($record['title'] ?? '') ?>" required placeholder="e.g., SQL Injection in Login Form">
            </div>

            <div class="col-md-6">
                <label for="engagementID" class="form-label">Engagement <span class="text-danger">*</span></label>
                <select class="form-select" id="engagementID" name="engagementID" required>
                    <option value="">— Select Engagement —</option>
                    <?php foreach ($engagements as $eng): ?>
                        <option value="<?= (int)$eng['engagementID'] ?>" <?= ((int)($record['engagementID'] ?? 0)) === (int)$eng['engagementID'] ? 'selected' : '' ?>><?= e($eng['engagementName']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="col-md-6">
                <label for="assetID" class="form-label">In-Scope Asset <span class="text-danger">*</span></label>
                <select class="form-select" id="assetID" name="assetID" required>
                    <option value="">— Select engagement first —</option>
                </select>
                <small class="text-muted">Only assets explicitly scoped into the selected engagement are accepted.</small>
            </div>

            <div class="col-md-6">
                <label for="vulnID" class="form-label">Linked Vulnerability</label>
                <select class="form-select" id="vulnID" name="vulnID">
                    <option value="">— Novel Finding (no linked CVE) —</option>
                    <?php foreach ($vulnerabilities as $v): ?>
                        <option value="<?= (int)$v['vulnID'] ?>" <?= ((int)($record['vulnID'] ?? 0)) === (int)$v['vulnID'] ? 'selected' : '' ?>>
                            <?= e(($v['cveID'] ?: 'Internal') . ' — ' . substr($v['title'], 0, 60)) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="col-md-6">
                <label for="discoveredByUserID" class="form-label">Discovered By</label>
                <select class="form-select" id="discoveredByUserID" name="discoveredByUserID">
                    <option value="">— Unassigned —</option>
                    <?php foreach ($users as $u): ?>
                        <option value="<?= (int)$u['userID'] ?>" <?= ((int)($record['discoveredByUserID'] ?? 0)) === (int)$u['userID'] ? 'selected' : '' ?>><?= e($u['fullName']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="col-md-4">
                <label for="riskRating" class="form-label">Risk Rating <span class="text-danger">*</span></label>
                <select class="form-select" id="riskRating" name="riskRating" required>
                    <option value="">— Select Rating —</option>
                    <?php foreach ($riskLevels as $r): ?>
                        <option value="<?= e($r) ?>" <?= ($record['riskRating'] ?? '') === $r ? 'selected' : '' ?>><?= e($r) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="col-md-4">
                <label for="reportedDate" class="form-label">Reported Date</label>
                <input type="date" class="form-control" id="reportedDate" name="reportedDate" value="<?= e($record['reportedDate'] ?? date('Y-m-d')) ?>">
            </div>

            <div class="col-md-4 d-flex align-items-end">
                <div class="form-check form-switch mb-2">
                    <input class="form-check-input" type="checkbox" id="exploitedSuccessfully" name="exploitedSuccessfully" value="1" <?= !empty($record['exploitedSuccessfully']) ? 'checked' : '' ?>>
                    <label class="form-check-label" for="exploitedSuccessfully">Exploited Successfully</label>
                </div>
            </div>

            <div class="col-12">
                <label for="proofOfConcept" class="form-label">Proof of Concept</label>
                <textarea class="form-control font-mono" id="proofOfConcept" name="proofOfConcept" rows="5" placeholder="Steps to reproduce, evidence, screenshots, etc."><?= e($record['proofOfConcept'] ?? '') ?></textarea>
            </div>

            <div class="col-12">
                <label for="recommendation" class="form-label">Recommendation</label>
                <textarea class="form-control" id="recommendation" name="recommendation" rows="4" placeholder="Remediation steps, mitigations, compensating controls…"><?= e($record['recommendation'] ?? '') ?></textarea>
            </div>
        </div>

        <div class="d-flex justify-content-between align-items-center mt-4 pt-3 border-top border-secondary">
            <a href="?page=findings/list" class="btn btn-outline-secondary"><i class="bi bi-x-lg me-1"></i> Cancel</a>
            <button type="submit" class="btn btn-cyber"><i class="bi bi-check-lg me-1"></i><?= $isEdit ? 'Update Finding' : 'Create Finding' ?></button>
        </div>
    </form>
</div>

<script>
(() => {
    const scopes = <?= json_encode($assetsByEngagement, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    const engagement = document.getElementById('engagementID');
    const asset = document.getElementById('assetID');
    const selectedAsset = <?= (int)($record['assetID'] ?? 0) ?>;

    function syncAssets() {
        const items = scopes[engagement.value] || [];
        asset.innerHTML = '<option value="">— Select in-scope asset —</option>';
        for (const item of items) {
            const option = document.createElement('option');
            option.value = item.assetID;
            option.textContent = item.assetName;
            if (Number(item.assetID) === Number(selectedAsset)) option.selected = true;
            asset.appendChild(option);
        }
    }

    engagement.addEventListener('change', syncAssets);
    syncAssets();
})();
</script>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
