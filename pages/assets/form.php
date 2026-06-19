<?php
$pageTitle = 'Asset';
$db = getDB();
$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$isEdit = $id > 0;
$entity = 'assets';

if (!canWrite($entity)) {
    flash('danger', 'Access denied.');
    redirect("?page={$entity}/list");
}

// Load existing record for edit
$record = null;
if ($isEdit) {
    $stmt = $db->prepare('SELECT * FROM assets WHERE assetID = :id');
    $stmt->execute([':id' => $id]);
    $record = $stmt->fetch();
    if (!$record) {
        flash('danger', 'Asset not found.');
        redirect("?page={$entity}/list");
    }
    $pageTitle = 'Edit Asset';
} else {
    $pageTitle = 'Create Asset';
}

// Fetch users for owner dropdown
$usersStmt = $db->query('SELECT userID, fullName FROM users WHERE isActive = 1 ORDER BY fullName');
$users = $usersStmt->fetchAll();

$assetTypes = ['Server', 'Workstation', 'Network_Device', 'Web_App', 'Database', 'Cloud_Resource', 'IoT_Device'];
$criticalities = ['Low', 'Medium', 'High', 'Critical'];
$environments = ['Production', 'Staging', 'Development', 'Test'];

// Handle form submission
$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCSRF();

    $assetName   = trim($_POST['assetName'] ?? '');
    $assetType   = $_POST['assetType'] ?? '';
    $ipAddress   = trim($_POST['ipAddress'] ?? '');
    $osPlatform  = trim($_POST['osPlatform'] ?? '');
    $ownerUserID = ($_POST['ownerUserID'] ?? '') !== '' ? (int)$_POST['ownerUserID'] : null;
    $criticality = $_POST['criticality'] ?? '';
    $environment = $_POST['environment'] ?? '';

    if ($assetName === '') $errors[] = 'Asset name is required.';
    if (!in_array($assetType, $assetTypes, true)) $errors[] = 'Invalid asset type.';
    if (!in_array($criticality, $criticalities, true)) $errors[] = 'Invalid criticality level.';
    if ($environment !== '' && !in_array($environment, $environments, true)) $errors[] = 'Invalid environment.';

    if (empty($errors)) {
        if ($isEdit) {
            $stmt = $db->prepare('UPDATE assets SET assetName = :name, assetType = :type, ipAddress = :ip, osPlatform = :os,
                                  ownerUserID = :owner, criticality = :crit, environment = :env WHERE assetID = :id');
            $stmt->execute([
                ':name'  => $assetName,
                ':type'  => $assetType,
                ':ip'    => $ipAddress ?: null,
                ':os'    => $osPlatform ?: null,
                ':owner' => $ownerUserID,
                ':crit'  => $criticality,
                ':env'   => $environment ?: null,
                ':id'    => $id
            ]);
            logAction('UPDATE', 'assets', $id, "Updated asset: {$assetName}");
            flash('success', 'Asset updated successfully.');
        } else {
            $stmt = $db->prepare('INSERT INTO assets (assetName, assetType, ipAddress, osPlatform, ownerUserID, criticality, environment)
                                  VALUES (:name, :type, :ip, :os, :owner, :crit, :env)');
            $stmt->execute([
                ':name'  => $assetName,
                ':type'  => $assetType,
                ':ip'    => $ipAddress ?: null,
                ':os'    => $osPlatform ?: null,
                ':owner' => $ownerUserID,
                ':crit'  => $criticality,
                ':env'   => $environment ?: null
            ]);
            $newId = (int)$db->lastInsertId();
            logAction('CREATE', 'assets', $newId, "Created asset: {$assetName}");
            flash('success', 'Asset created successfully.');
        }
        redirect("?page={$entity}/list");
    }
}

require __DIR__ . '/../../includes/header.php';
?>

<div class="page-header fade-in-up">
    <div>
        <h1 class="h3 mb-1">
            <i class="bi bi-<?= $isEdit ? 'pencil-square' : 'hdd-rack-fill' ?> me-2"></i><?= e($pageTitle) ?>
        </h1>
        <p class="text-secondary mb-0"><?= $isEdit ? 'Modify asset configuration' : 'Register a new organizational asset' ?></p>
    </div>
    <a href="?page=assets/list" class="btn btn-cyber-outline"><i class="bi bi-arrow-left me-1"></i>Back to Assets</a>
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
    <form method="POST" action="?page=assets/form<?= $isEdit ? '&id=' . $id : '' ?>">
        <?= csrfField() ?>

        <div class="row g-4">
            <div class="col-md-6">
                <label for="assetName" class="form-label">Asset Name <span class="text-danger">*</span></label>
                <input type="text" class="form-control bg-dark text-light border-secondary" id="assetName" name="assetName"
                       value="<?= e($record['assetName'] ?? ($_POST['assetName'] ?? '')) ?>" required>
            </div>

            <div class="col-md-6">
                <label for="assetType" class="form-label">Asset Type <span class="text-danger">*</span></label>
                <select class="form-select bg-dark text-light border-secondary" id="assetType" name="assetType" required>
                    <option value="">— Select Type —</option>
                    <?php
                    $currentType = $record['assetType'] ?? ($_POST['assetType'] ?? '');
                    foreach ($assetTypes as $t):
                    ?>
                        <option value="<?= e($t) ?>" <?= $currentType === $t ? 'selected' : '' ?>><?= e(str_replace('_', ' ', $t)) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="col-md-6">
                <label for="ipAddress" class="form-label">IP Address</label>
                <input type="text" class="form-control bg-dark text-light border-secondary font-mono" id="ipAddress" name="ipAddress"
                       value="<?= e($record['ipAddress'] ?? ($_POST['ipAddress'] ?? '')) ?>" placeholder="e.g. 192.168.1.100">
            </div>

            <div class="col-md-6">
                <label for="osPlatform" class="form-label">OS / Platform</label>
                <input type="text" class="form-control bg-dark text-light border-secondary" id="osPlatform" name="osPlatform"
                       value="<?= e($record['osPlatform'] ?? ($_POST['osPlatform'] ?? '')) ?>" placeholder="e.g. Ubuntu 22.04, Windows Server 2022">
            </div>

            <div class="col-md-4">
                <label for="ownerUserID" class="form-label">Owner</label>
                <select class="form-select bg-dark text-light border-secondary" id="ownerUserID" name="ownerUserID">
                    <option value="">— No Owner —</option>
                    <?php
                    $currentOwner = $record['ownerUserID'] ?? ($_POST['ownerUserID'] ?? '');
                    foreach ($users as $u):
                    ?>
                        <option value="<?= (int)$u['userID'] ?>" <?= (string)$currentOwner === (string)$u['userID'] ? 'selected' : '' ?>><?= e($u['fullName']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="col-md-4">
                <label for="criticality" class="form-label">Criticality <span class="text-danger">*</span></label>
                <select class="form-select bg-dark text-light border-secondary" id="criticality" name="criticality" required>
                    <option value="">— Select Level —</option>
                    <?php
                    $currentCrit = $record['criticality'] ?? ($_POST['criticality'] ?? '');
                    foreach ($criticalities as $c):
                    ?>
                        <option value="<?= e($c) ?>" <?= $currentCrit === $c ? 'selected' : '' ?>><?= e($c) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="col-md-4">
                <label for="environment" class="form-label">Environment</label>
                <select class="form-select bg-dark text-light border-secondary" id="environment" name="environment">
                    <option value="">— Select —</option>
                    <?php
                    $currentEnv = $record['environment'] ?? ($_POST['environment'] ?? '');
                    foreach ($environments as $env):
                    ?>
                        <option value="<?= e($env) ?>" <?= $currentEnv === $env ? 'selected' : '' ?>><?= e($env) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
        </div>

        <hr class="border-secondary my-4">

        <div class="d-flex gap-2">
            <button type="submit" class="btn btn-cyber">
                <i class="bi bi-check-lg me-1"></i><?= $isEdit ? 'Update Asset' : 'Create Asset' ?>
            </button>
            <a href="?page=assets/list" class="btn btn-cyber-outline">Cancel</a>
        </div>
    </form>
</div>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
