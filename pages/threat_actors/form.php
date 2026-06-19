<?php
/**
 * CTVLMS — Threat Actors: Create / Edit Form
 */

$db = getDB();
$entity = 'threat_actors';
$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$isEdit = $id > 0;
$pageTitle = $isEdit ? 'Edit Threat Actor' : 'New Threat Actor';

// ---- Access check ----
if (!canWrite($entity)) {
    flash('danger', 'Access denied.');
    redirect('?page=threat_actors/list');
}

// ---- Load existing record for edit ----
$record = null;
if ($isEdit) {
    $stmt = $db->prepare('SELECT * FROM threat_actors WHERE actorID = :id');
    $stmt->execute([':id' => $id]);
    $record = $stmt->fetch();
    if (!$record) {
        flash('danger', 'Threat actor not found.');
        redirect('?page=threat_actors/list');
    }
}

// ---- ENUM options ----
$motivations = ['Financial', 'Espionage', 'Hacktivism', 'Disruption', 'Unknown'];

// ---- Handle form submission ----
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCSRF();

    $actorName    = trim($_POST['actorName'] ?? '');
    $aliasNames   = trim($_POST['aliasNames'] ?? '');
    $motivation   = $_POST['motivation'] ?? '';
    $originCountry = trim($_POST['originCountry'] ?? '');
    $description  = trim($_POST['description'] ?? '');

    // Validate
    $errors = [];
    if ($actorName === '') {
        $errors[] = 'Actor name is required.';
    }
    if (!in_array($motivation, $motivations, true)) {
        $errors[] = 'Invalid motivation selected.';
    }

    if (!empty($errors)) {
        foreach ($errors as $err) {
            flash('danger', $err);
        }
    } else {
        if ($isEdit) {
            $stmt = $db->prepare(
                'UPDATE threat_actors
                    SET actorName = :actorName,
                        aliasNames = :aliasNames,
                        motivation = :motivation,
                        originCountry = :originCountry,
                        description = :description
                  WHERE actorID = :id'
            );
            $stmt->execute([
                ':actorName'     => $actorName,
                ':aliasNames'    => $aliasNames ?: null,
                ':motivation'    => $motivation,
                ':originCountry' => $originCountry ?: null,
                ':description'   => $description ?: null,
                ':id'            => $id,
            ]);
            logAction('UPDATE', 'threat_actors', $id, "Updated threat actor: {$actorName}");
            flash('success', 'Threat actor updated successfully.');
        } else {
            $stmt = $db->prepare(
                'INSERT INTO threat_actors (actorName, aliasNames, motivation, originCountry, description)
                 VALUES (:actorName, :aliasNames, :motivation, :originCountry, :description)'
            );
            $stmt->execute([
                ':actorName'     => $actorName,
                ':aliasNames'    => $aliasNames ?: null,
                ':motivation'    => $motivation,
                ':originCountry' => $originCountry ?: null,
                ':description'   => $description ?: null,
            ]);
            $newId = (int)$db->lastInsertId();
            logAction('INSERT', 'threat_actors', $newId, "Created threat actor: {$actorName}");
            flash('success', 'Threat actor created successfully.');
        }
        redirect('?page=threat_actors/list');
    }
}

// ---- Populate form values (POST on error or existing record) ----
$f = [
    'actorName'     => $_POST['actorName']     ?? ($record['actorName'] ?? ''),
    'aliasNames'    => $_POST['aliasNames']    ?? ($record['aliasNames'] ?? ''),
    'motivation'    => $_POST['motivation']    ?? ($record['motivation'] ?? 'Unknown'),
    'originCountry' => $_POST['originCountry'] ?? ($record['originCountry'] ?? ''),
    'description'   => $_POST['description']   ?? ($record['description'] ?? ''),
];

require __DIR__ . '/../../includes/header.php';
?>

<!-- Page Header -->
<div class="page-header">
    <div>
        <h1 class="h3 mb-0">
            <i class="bi bi-person-badge me-2"></i><?= e($pageTitle) ?>
        </h1>
        <small class="text-muted">
            <?= $isEdit ? 'Editing: ' . e($record['actorName']) : 'Register a new threat actor' ?>
        </small>
    </div>
    <a href="?page=threat_actors/list" class="btn btn-cyber-outline">
        <i class="bi bi-arrow-left me-1"></i> Back to List
    </a>
</div>

<!-- Form -->
<div class="glass-card fade-in-up" style="max-width:750px;">
    <form method="POST" action="?page=threat_actors/form<?= $isEdit ? '&id=' . $id : '' ?>">
        <?= csrfField() ?>

        <!-- Actor Name -->
        <div class="mb-3">
            <label for="actorName" class="form-label">Actor Name <span class="text-danger">*</span></label>
            <input type="text" class="form-control" id="actorName" name="actorName"
                   value="<?= e($f['actorName']) ?>" required maxlength="150" placeholder="e.g. APT29, Lazarus Group">
        </div>

        <!-- Alias Names -->
        <div class="mb-3">
            <label for="aliasNames" class="form-label">Alias Names</label>
            <input type="text" class="form-control" id="aliasNames" name="aliasNames"
                   value="<?= e($f['aliasNames']) ?>" maxlength="255"
                   placeholder="e.g. Cozy Bear, The Dukes (comma-separated)">
            <div class="form-text">Comma-separated list of known aliases.</div>
        </div>

        <div class="row g-3">
            <!-- Motivation -->
            <div class="col-md-6 mb-3">
                <label for="motivation" class="form-label">Motivation <span class="text-danger">*</span></label>
                <select class="form-select" id="motivation" name="motivation" required>
                    <?php foreach ($motivations as $m): ?>
                    <option value="<?= e($m) ?>" <?= $f['motivation'] === $m ? 'selected' : '' ?>>
                        <?= e($m) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Origin Country -->
            <div class="col-md-6 mb-3">
                <label for="originCountry" class="form-label">Origin Country</label>
                <input type="text" class="form-control" id="originCountry" name="originCountry"
                       value="<?= e($f['originCountry']) ?>" maxlength="100" placeholder="e.g. Russia, China, Iran">
            </div>
        </div>

        <!-- Description -->
        <div class="mb-4">
            <label for="description" class="form-label">Description</label>
            <textarea class="form-control" id="description" name="description" rows="5"
                      placeholder="Background, TTPs, notable campaigns..."><?= e($f['description']) ?></textarea>
        </div>

        <!-- Submit -->
        <div class="d-flex gap-2">
            <button type="submit" class="btn btn-cyber">
                <i class="bi bi-check-lg me-1"></i> <?= $isEdit ? 'Update Threat Actor' : 'Create Threat Actor' ?>
            </button>
            <a href="?page=threat_actors/list" class="btn btn-cyber-outline">Cancel</a>
        </div>
    </form>
</div>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
