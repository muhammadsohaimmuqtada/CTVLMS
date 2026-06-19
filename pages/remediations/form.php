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

// Load existing record for edit
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

// Fetch asset-vulnerability mappings for the select dropdown
$assetVulnsStmt = $db->query(
    'SELECT av.assetVulnID, a.assetName, v.title AS vulnTitle 
     FROM asset_vulnerabilities av 
     JOIN assets a ON av.assetID = a.assetID 
     JOIN vulnerabilities v ON av.vulnID = v.vulnID 
     ORDER BY a.assetName, v.title'
);
$assetVulns = $assetVulnsStmt->fetchAll();

// Fetch users for assignment/verification dropdowns
$usersStmt = $db->query('SELECT userID, fullName FROM users ORDER BY fullName');
$users = $usersStmt->fetchAll();

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCSRF();
    
    $assetVulnID = $_POST['assetVulnID'] ?? null;
    $assignedToUserID = !empty($_POST['assignedToUserID']) ? $_POST['assignedToUserID'] : null;
    $actionTaken = $_POST['actionTaken'] ?? '';
    $remediationType = $_POST['remediationType'] ?? '';
    $startedDate = !empty($_POST['startedDate']) ? $_POST['startedDate'] : null;
    $completedDate = !empty($_POST['completedDate']) ? $_POST['completedDate'] : null;
    $verifiedByUserID = !empty($_POST['verifiedByUserID']) ? $_POST['verifiedByUserID'] : null;
    $verificationDate = !empty($_POST['verificationDate']) ? $_POST['verificationDate'] : null;
    
    // Validate required fields
    if (empty($assetVulnID) || empty($actionTaken) || empty($remediationType)) {
        flash('danger', 'Please fill in all required fields.');
    } else {
        if ($isEdit) {
            $sql = 'UPDATE remediations SET 
                    assetVulnID = :assetVulnID, assignedToUserID = :assignedToUserID, 
                    actionTaken = :actionTaken, remediationType = :remediationType, 
                    startedDate = :startedDate, completedDate = :completedDate, 
                    verifiedByUserID = :verifiedByUserID, verificationDate = :verificationDate 
                    WHERE remediationID = :id';
            $stmt = $db->prepare($sql);
            $stmt->execute([
                ':assetVulnID' => $assetVulnID,
                ':assignedToUserID' => $assignedToUserID,
                ':actionTaken' => $actionTaken,
                ':remediationType' => $remediationType,
                ':startedDate' => $startedDate,
                ':completedDate' => $completedDate,
                ':verifiedByUserID' => $verifiedByUserID,
                ':verificationDate' => $verificationDate,
                ':id' => $id
            ]);
            logAction('UPDATE', 'remediations', $id, 'Updated remediation record');
            flash('success', 'Remediation updated successfully.');
        } else {
            $sql = 'INSERT INTO remediations (assetVulnID, assignedToUserID, actionTaken, remediationType, startedDate, completedDate, verifiedByUserID, verificationDate) 
                    VALUES (:assetVulnID, :assignedToUserID, :actionTaken, :remediationType, :startedDate, :completedDate, :verifiedByUserID, :verificationDate)';
            $stmt = $db->prepare($sql);
            $stmt->execute([
                ':assetVulnID' => $assetVulnID,
                ':assignedToUserID' => $assignedToUserID,
                ':actionTaken' => $actionTaken,
                ':remediationType' => $remediationType,
                ':startedDate' => $startedDate,
                ':completedDate' => $completedDate,
                ':verifiedByUserID' => $verifiedByUserID,
                ':verificationDate' => $verificationDate
            ]);
            $newId = $db->lastInsertId();
            logAction('CREATE', 'remediations', $newId, 'Created new remediation record');
            flash('success', 'Remediation created successfully.');
        }
        redirect("?page={$entity}/list");
    }
}

require __DIR__ . '/../../includes/header.php';
?>

<div class="page-header fade-in-up">
    <h2>
        <i class="bi bi-wrench"></i> 
        <?= $isEdit ? 'Edit Remediation' : 'Log Remediation Action' ?>
    </h2>
    <a href="?page=remediations/list" class="btn btn-cyber-outline">
        <i class="bi bi-arrow-left"></i> Back to Remediations
    </a>
</div>

<div class="glass-card fade-in-up" style="animation-delay: 0.1s;">
    <div class="card-body p-4">
        <form method="POST" action="?page=remediations/form<?= $isEdit ? '&id=' . $id : '' ?>">
            <?= csrfField() ?>
            
            <div class="row mb-3">
                <div class="col-md-8">
                    <label class="form-label">Target Asset & Vulnerability <span class="text-danger">*</span></label>
                    <select name="assetVulnID" class="form-select" required>
                        <option value="">-- Select Target --</option>
                        <?php foreach ($assetVulns as $av): ?>
                            <option value="<?= $av['assetVulnID'] ?>" <?= ($record['assetVulnID'] ?? '') == $av['assetVulnID'] ? 'selected' : '' ?>>
                                <?= e($av['assetName']) ?> — <?= e($av['vulnTitle']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-4">
                    <label class="form-label">Remediation Type <span class="text-danger">*</span></label>
                    <select name="remediationType" class="form-select" required>
                        <option value="">-- Select Type --</option>
                        <?php 
                        $types = ['Patch', 'Configuration_Change', 'Compensating_Control', 'Decommission', 'Risk_Acceptance'];
                        foreach ($types as $t): 
                        ?>
                            <option value="<?= $t ?>" <?= ($record['remediationType'] ?? '') === $t ? 'selected' : '' ?>><?= e(str_replace('_', ' ', $t)) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </div>

            <div class="mb-3">
                <label class="form-label">Action Taken / Details <span class="text-danger">*</span></label>
                <textarea name="actionTaken" class="form-control" rows="4" required><?= e($record['actionTaken'] ?? '') ?></textarea>
            </div>
            
            <div class="row mb-3">
                <div class="col-md-6">
                    <label class="form-label">Assigned To</label>
                    <select name="assignedToUserID" class="form-select">
                        <option value="">-- Unassigned --</option>
                        <?php foreach ($users as $u): ?>
                            <option value="<?= $u['userID'] ?>" <?= ($record['assignedToUserID'] ?? '') == $u['userID'] ? 'selected' : '' ?>>
                                <?= e($u['fullName']) ?>
                            </option>
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
            
            <div class="row mb-4">
                <div class="col-md-6">
                    <label class="form-label">Verified By</label>
                    <select name="verifiedByUserID" class="form-select">
                        <option value="">-- Pending Verification --</option>
                        <?php foreach ($users as $u): ?>
                            <option value="<?= $u['userID'] ?>" <?= ($record['verifiedByUserID'] ?? '') == $u['userID'] ? 'selected' : '' ?>>
                                <?= e($u['fullName']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-6">
                    <label class="form-label">Verification Date</label>
                    <input type="date" name="verificationDate" class="form-control" value="<?= e($record['verificationDate'] ?? '') ?>">
                </div>
            </div>

            <hr class="border-glass mb-4">
            
            <div class="d-flex justify-content-end gap-2">
                <a href="?page=remediations/list" class="btn btn-secondary">Cancel</a>
                <button type="submit" class="btn btn-cyber">
                    <i class="bi bi-save"></i> <?= $isEdit ? 'Save Changes' : 'Create Remediation' ?>
                </button>
            </div>
        </form>
    </div>
</div>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
