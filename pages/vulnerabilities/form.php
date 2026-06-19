<?php
$pageTitle = 'Vulnerability';
$db = getDB();
$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$isEdit = $id > 0;
$entity = 'vulnerabilities';

if (!canWrite($entity)) {
    flash('danger', 'Access denied.');
    redirect("?page={$entity}/list");
}

// Load existing record for edit
$record = null;
if ($isEdit) {
    $stmt = $db->prepare('SELECT * FROM vulnerabilities WHERE vulnID = :id');
    $stmt->execute([':id' => $id]);
    $record = $stmt->fetch();
    if (!$record) {
        flash('danger', 'Vulnerability not found.');
        redirect("?page={$entity}/list");
    }
    $pageTitle = 'Edit Vulnerability';
} else {
    $pageTitle = 'Create Vulnerability';
}

$severities = ['Low', 'Medium', 'High', 'Critical'];

// Handle form submission
$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCSRF();

    $cveID         = trim($_POST['cveID'] ?? '');
    $title         = trim($_POST['title'] ?? '');
    $description   = trim($_POST['description'] ?? '');
    $cvssScore     = $_POST['cvssScore'] ?? '';
    $severity      = $_POST['severity'] ?? '';
    $cwe           = trim($_POST['cwe'] ?? '');
    $publishedDate = $_POST['publishedDate'] ?? '';

    if ($title === '') $errors[] = 'Title is required.';
    if (!in_array($severity, $severities, true)) $errors[] = 'Invalid severity level.';

    if ($cvssScore !== '') {
        $cvssFloat = (float)$cvssScore;
        if ($cvssFloat < 0 || $cvssFloat > 10) {
            $errors[] = 'CVSS Score must be between 0 and 10.';
        }
    }

    if (empty($errors)) {
        $data = [
            ':cve'   => $cveID ?: null,
            ':title' => $title,
            ':desc'  => $description ?: null,
            ':cvss'  => $cvssScore !== '' ? (float)$cvssScore : null,
            ':sev'   => $severity,
            ':cwe'   => $cwe ?: null,
            ':pub'   => $publishedDate ?: null,
        ];

        if ($isEdit) {
            $stmt = $db->prepare('UPDATE vulnerabilities SET cveID = :cve, title = :title, description = :desc,
                                  cvssScore = :cvss, severity = :sev, cwe = :cwe, publishedDate = :pub WHERE vulnID = :id');
            $data[':id'] = $id;
            $stmt->execute($data);
            logAction('UPDATE', 'vulnerabilities', $id, "Updated vulnerability: {$title}");
            flash('success', 'Vulnerability updated successfully.');
        } else {
            $stmt = $db->prepare('INSERT INTO vulnerabilities (cveID, title, description, cvssScore, severity, cwe, publishedDate)
                                  VALUES (:cve, :title, :desc, :cvss, :sev, :cwe, :pub)');
            $stmt->execute($data);
            $newId = (int)$db->lastInsertId();
            logAction('CREATE', 'vulnerabilities', $newId, "Created vulnerability: {$title}");
            flash('success', 'Vulnerability created successfully.');
        }
        redirect("?page={$entity}/list");
    }
}

require __DIR__ . '/../../includes/header.php';
?>

<div class="page-header fade-in-up">
    <div>
        <h1 class="h3 mb-1">
            <i class="bi bi-<?= $isEdit ? 'pencil-square' : 'shield-plus' ?> me-2"></i><?= e($pageTitle) ?>
        </h1>
        <p class="text-secondary mb-0"><?= $isEdit ? 'Modify vulnerability details' : 'Register a new vulnerability entry' ?></p>
    </div>
    <a href="?page=vulnerabilities/list" class="btn btn-cyber-outline"><i class="bi bi-arrow-left me-1"></i>Back to Vulnerabilities</a>
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
    <form method="POST" action="?page=vulnerabilities/form<?= $isEdit ? '&id=' . $id : '' ?>">
        <?= csrfField() ?>

        <div class="row g-4">
            <div class="col-md-4">
                <label for="cveID" class="form-label">CVE ID <span class="text-secondary small">(optional)</span></label>
                <input type="text" class="form-control bg-dark text-light border-secondary font-mono" id="cveID" name="cveID"
                       value="<?= e($record['cveID'] ?? ($_POST['cveID'] ?? '')) ?>" placeholder="CVE-2024-XXXXX">
            </div>

            <div class="col-md-8">
                <label for="title" class="form-label">Title <span class="text-danger">*</span></label>
                <input type="text" class="form-control bg-dark text-light border-secondary" id="title" name="title"
                       value="<?= e($record['title'] ?? ($_POST['title'] ?? '')) ?>" required>
            </div>

            <div class="col-12">
                <label for="description" class="form-label">Description</label>
                <textarea class="form-control bg-dark text-light border-secondary" id="description" name="description"
                          rows="4" placeholder="Detailed vulnerability description..."><?= e($record['description'] ?? ($_POST['description'] ?? '')) ?></textarea>
            </div>

            <div class="col-md-3">
                <label for="cvssScore" class="form-label">CVSS Score</label>
                <input type="number" class="form-control bg-dark text-light border-secondary" id="cvssScore" name="cvssScore"
                       value="<?= e($record['cvssScore'] ?? ($_POST['cvssScore'] ?? '')) ?>" step="0.1" min="0" max="10" placeholder="0.0 – 10.0">
            </div>

            <div class="col-md-3">
                <label for="severity" class="form-label">Severity <span class="text-danger">*</span></label>
                <select class="form-select bg-dark text-light border-secondary" id="severity" name="severity" required>
                    <option value="">— Select —</option>
                    <?php
                    $currentSev = $record['severity'] ?? ($_POST['severity'] ?? '');
                    foreach ($severities as $s):
                    ?>
                        <option value="<?= e($s) ?>" <?= $currentSev === $s ? 'selected' : '' ?>><?= e($s) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="col-md-3">
                <label for="cwe" class="form-label">CWE</label>
                <input type="text" class="form-control bg-dark text-light border-secondary font-mono" id="cwe" name="cwe"
                       value="<?= e($record['cwe'] ?? ($_POST['cwe'] ?? '')) ?>" placeholder="CWE-79">
            </div>

            <div class="col-md-3">
                <label for="publishedDate" class="form-label">Published Date</label>
                <input type="date" class="form-control bg-dark text-light border-secondary" id="publishedDate" name="publishedDate"
                       value="<?= e($record['publishedDate'] ?? ($_POST['publishedDate'] ?? '')) ?>">
            </div>
        </div>

        <hr class="border-secondary my-4">

        <div class="d-flex gap-2">
            <button type="submit" class="btn btn-cyber">
                <i class="bi bi-check-lg me-1"></i><?= $isEdit ? 'Update Vulnerability' : 'Create Vulnerability' ?>
            </button>
            <a href="?page=vulnerabilities/list" class="btn btn-cyber-outline">Cancel</a>
        </div>
    </form>
</div>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
