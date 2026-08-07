<?php
$pageTitle = 'Exposure Intelligence';
$db = getDB();

$statusFilter = $_GET['status'] ?? '';
$allowedStatuses = ['Potential','Confirmed','Not_Affected','Remediation_Queued','Remediating','Remediated','Verification_Failed','Verified_Closed'];
$where = '';
$params = [];
if ($statusFilter !== '' && in_array($statusFilter, $allowedStatuses, true)) {
    $where = 'WHERE e.status = :status';
    $params[':status'] = $statusFilter;
}

$stmt = $db->prepare(
    "SELECT e.*, a.assetName, a.ipAddress, a.criticality,
            v.cveID, v.title AS vulnTitle, v.severity, v.cvssScore,
            s.product AS softwareProduct, s.version AS softwareVersion, s.cpe AS softwareCpe,
            svc.product AS serviceProduct, svc.version AS serviceVersion, svc.cpe AS serviceCpe,
            svc.port AS servicePort, svc.protocol AS serviceProtocol,
            j.jobID, j.status AS jobStatus, j.packageName, j.fromVersion, j.targetVersion
     FROM exposure_matches e
     JOIN assets a ON a.assetID = e.assetID
     JOIN vulnerabilities v ON v.vulnID = e.vulnID
     LEFT JOIN asset_software s ON s.softwareID = e.softwareID
     LEFT JOIN asset_services svc ON svc.serviceID = e.serviceID
     LEFT JOIN remediation_jobs j ON j.jobID = (
         SELECT j2.jobID FROM remediation_jobs j2
         WHERE j2.exposureID = e.exposureID
         ORDER BY j2.requestedAt DESC LIMIT 1
     )
     {$where}
     ORDER BY
        FIELD(e.status, 'Verification_Failed','Confirmed','Potential','Remediation_Queued','Remediating','Remediated','Verified_Closed','Not_Affected'),
        v.cvssScore DESC,
        e.lastEvaluated DESC"
);
$stmt->execute($params);
$rows = $stmt->fetchAll();

$counts = array_fill_keys($allowedStatuses, 0);
foreach ($db->query('SELECT status, COUNT(*) AS c FROM exposure_matches GROUP BY status')->fetchAll() as $row) {
    $counts[$row['status']] = (int)$row['c'];
}

function exposureBadge(string $status): string
{
    $class = match ($status) {
        'Confirmed', 'Verification_Failed' => 'badge-critical',
        'Potential', 'Remediation_Queued' => 'badge-high',
        'Remediating', 'Remediated' => 'badge-medium',
        'Verified_Closed' => 'badge-low',
        default => 'bg-secondary',
    };
    return '<span class="badge ' . $class . '">' . e(str_replace('_', ' ', $status)) . '</span>';
}

require __DIR__ . '/../../includes/header.php';
?>

<div class="page-header fade-in-up">
    <div>
        <h1 class="h3 mb-1"><i class="bi bi-radar me-2"></i>Exposure Intelligence</h1>
        <p class="text-secondary mb-0">Evidence-backed asset/CVE applicability and remediation state</p>
    </div>
</div>

<div class="row g-3 mb-4">
    <?php foreach (['Confirmed','Potential','Remediation_Queued','Remediating','Verification_Failed','Verified_Closed'] as $state): ?>
        <div class="col-6 col-md-2">
            <a class="text-decoration-none" href="?page=exposures/list&status=<?= e($state) ?>">
                <div class="glass-card p-3 h-100">
                    <div class="text-secondary small"><?= e(str_replace('_', ' ', $state)) ?></div>
                    <div class="h3 mb-0"><?= (int)$counts[$state] ?></div>
                </div>
            </a>
        </div>
    <?php endforeach; ?>
</div>

<div class="filter-bar fade-in-up">
    <form method="GET" class="row g-3 align-items-end">
        <input type="hidden" name="page" value="exposures/list">
        <div class="col-md-4">
            <label class="form-label text-secondary small">Exposure Status</label>
            <select class="form-select bg-dark text-light border-secondary" name="status" onchange="this.form.submit()">
                <option value="">All statuses</option>
                <?php foreach ($allowedStatuses as $state): ?>
                    <option value="<?= e($state) ?>" <?= $statusFilter === $state ? 'selected' : '' ?>><?= e(str_replace('_', ' ', $state)) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-auto ms-auto"><span class="badge bg-secondary"><?= count($rows) ?> exposure<?= count($rows) === 1 ? '' : 's' ?></span></div>
    </form>
</div>

<div class="glass-card p-0 fade-in-up">
    <div class="table-responsive">
        <table class="table table-dark-custom table-hover mb-0">
            <thead>
                <tr>
                    <th>Asset</th>
                    <th>Vulnerability</th>
                    <th>Observed Evidence</th>
                    <th>Match</th>
                    <th>Status</th>
                    <th>Remediation</th>
                    <th>Evaluated</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!$rows): ?>
                <tr><td colspan="7" class="text-center py-5 text-secondary">No exposure matches for this filter.</td></tr>
            <?php endif; ?>
            <?php foreach ($rows as $row): ?>
                <?php
                $product = $row['softwareProduct'] ?: $row['serviceProduct'];
                $version = $row['softwareVersion'] ?: $row['serviceVersion'];
                $cpe = $row['softwareCpe'] ?: $row['serviceCpe'];
                ?>
                <tr>
                    <td>
                        <strong><?= e($row['assetName']) ?></strong><br>
                        <span class="font-mono text-secondary small"><?= e($row['ipAddress'] ?? 'no IP') ?></span><br>
                        <?= criticalityBadge($row['criticality']) ?>
                    </td>
                    <td style="min-width:260px">
                        <span class="font-mono text-info"><?= e($row['cveID'] ?? 'Internal') ?></span>
                        <?= severityBadge($row['severity']) ?><br>
                        <span class="small"><?= e(substr($row['vulnTitle'], 0, 100)) ?></span>
                    </td>
                    <td style="min-width:260px">
                        <strong><?= e($product ?: 'Unknown product') ?></strong>
                        <span class="font-mono"><?= e($version ?: 'unknown version') ?></span>
                        <?php if ($row['servicePort']): ?>
                            <div class="small text-secondary"><?= e($row['serviceProtocol']) ?>/<?= (int)$row['servicePort'] ?></div>
                        <?php endif; ?>
                        <?php if ($cpe): ?>
                            <div class="font-mono small text-secondary text-break" title="<?= e($cpe) ?>"><?= e($cpe) ?></div>
                        <?php endif; ?>
                    </td>
                    <td>
                        <span class="badge bg-secondary"><?= e(str_replace('_', ' ', $row['matchType'])) ?></span><br>
                        <span class="small text-secondary"><?= e(number_format((float)$row['confidence'] * 100, 1)) ?>% confidence</span>
                    </td>
                    <td><?= exposureBadge($row['status']) ?></td>
                    <td>
                        <?php if ($row['jobID']): ?>
                            <span class="font-mono">Job #<?= (int)$row['jobID'] ?></span><br>
                            <span class="badge bg-secondary"><?= e(str_replace('_', ' ', $row['jobStatus'])) ?></span>
                            <?php if ($row['packageName']): ?><div class="small"><?= e($row['packageName']) ?></div><?php endif; ?>
                            <?php if ($row['targetVersion']): ?><div class="small text-secondary"><?= e($row['fromVersion']) ?> → <?= e($row['targetVersion']) ?></div><?php endif; ?>
                        <?php else: ?>
                            <span class="text-secondary">Not queued</span>
                        <?php endif; ?>
                    </td>
                    <td class="text-secondary small"><?= e(date('M j, Y H:i', strtotime($row['lastEvaluated']))) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?php require __DIR__ . '/../../includes/footer.php'; ?>
