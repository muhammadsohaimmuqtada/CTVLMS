<?php
/**
 * CTVLMS — Dashboard
 */

$pageTitle = 'Dashboard';
$db = getDB();

// ── Summary Card Counts ──────────────────────────────────────────────

$totalAssets = (int)$db->query('SELECT COUNT(*) FROM assets')->fetchColumn();

$stmtOpenVulns = $db->query(
    "SELECT COUNT(*) FROM asset_vulnerabilities
     WHERE status NOT IN ('Remediated','Verified_Closed','Risk_Accepted')"
);
$openVulns = (int)$stmtOpenVulns->fetchColumn();

$stmtActiveIncidents = $db->query(
    "SELECT COUNT(*) FROM incidents
     WHERE status NOT IN ('Closed','Recovered')"
);
$activeIncidents = (int)$stmtActiveIncidents->fetchColumn();

$stmtActiveEngagements = $db->query(
    "SELECT COUNT(*) FROM engagements WHERE status = 'In_Progress'"
);
$activeEngagements = (int)$stmtActiveEngagements->fetchColumn();

// ── Chart Data ───────────────────────────────────────────────────────

// 1. Doughnut: Vulnerability severity distribution
$sevRows = $db->query(
    'SELECT severity, COUNT(*) AS cnt FROM vulnerabilities GROUP BY severity'
)->fetchAll();
$sevLabels = array_column($sevRows, 'severity');
$sevData   = array_map('intval', array_column($sevRows, 'cnt'));

// 2. Bar: Open vulns by asset criticality
$critRows = $db->query(
    "SELECT a.criticality, COUNT(*) AS cnt
     FROM asset_vulnerabilities av
     JOIN assets a ON av.assetID = a.assetID
     WHERE av.status NOT IN ('Remediated','Verified_Closed','Risk_Accepted')
     GROUP BY a.criticality"
)->fetchAll();
$critLabels = array_column($critRows, 'criticality');
$critData   = array_map('intval', array_column($critRows, 'cnt'));

// 3. Horizontal Bar: Top 5 most attacked assets
$atkRows = $db->query(
    'SELECT a.assetName, COUNT(i.incidentID) AS incidentCount
     FROM assets a
     JOIN incidents i ON a.assetID = i.assetID
     GROUP BY a.assetID, a.assetName
     ORDER BY incidentCount DESC
     LIMIT 5'
)->fetchAll();
$atkLabels = array_column($atkRows, 'assetName');
$atkData   = array_map('intval', array_column($atkRows, 'incidentCount'));

// 4. Line: Incidents over last 6 months
$incRows = $db->query(
    "SELECT DATE_FORMAT(detectedDate, '%Y-%m') AS month, COUNT(*) AS cnt
     FROM incidents
     GROUP BY month
     ORDER BY month"
)->fetchAll();
$incLabels = array_column($incRows, 'month');
$incData   = array_map('intval', array_column($incRows, 'cnt'));

// ── Attention Feed ───────────────────────────────────────────────────

$feedItems = $db->query(
    "SELECT 'Vulnerability' AS itemType, v.title AS itemTitle, v.severity AS priority, av.discoveredDate AS dateRaised
     FROM asset_vulnerabilities av
     JOIN vulnerabilities v ON av.vulnID = v.vulnID
     WHERE av.status = 'Discovered'
     UNION
     SELECT 'Incident' AS itemType, i.title AS itemTitle, i.severity AS priority, DATE(i.detectedDate) AS dateRaised
     FROM incidents i
     WHERE i.status = 'Open'
     ORDER BY priority DESC, dateRaised ASC
     LIMIT 15"
)->fetchAll();

require __DIR__ . '/../includes/header.php';
?>

<!-- ── Summary Cards ──────────────────────────────────────────────── -->
<div class="page-header">
    <h2><i class="bi bi-speedometer2"></i> Dashboard</h2>
    <span class="text-muted small"><i class="bi bi-clock"></i> <?= e(date('F j, Y · g:i A')) ?></span>
</div>

<div class="row g-4 mb-4">
    <!-- Total Assets -->
    <div class="col-sm-6 col-xl-3">
        <div class="summary-card fade-in-up">
            <i class="bi bi-hdd-rack card-icon"></i>
            <div class="card-value"><?= e((string)$totalAssets) ?></div>
            <div class="card-label">Total Assets</div>
        </div>
    </div>
    <!-- Open Vulnerabilities -->
    <div class="col-sm-6 col-xl-3">
        <div class="summary-card critical fade-in-up" style="animation-delay:0.1s">
            <i class="bi bi-bug card-icon"></i>
            <div class="card-value"><?= e((string)$openVulns) ?></div>
            <div class="card-label">Open Vulnerabilities</div>
        </div>
    </div>
    <!-- Active Incidents -->
    <div class="col-sm-6 col-xl-3">
        <div class="summary-card warning fade-in-up" style="animation-delay:0.2s">
            <i class="bi bi-exclamation-triangle card-icon"></i>
            <div class="card-value"><?= e((string)$activeIncidents) ?></div>
            <div class="card-label">Active Incidents</div>
        </div>
    </div>
    <!-- Active Engagements -->
    <div class="col-sm-6 col-xl-3">
        <div class="summary-card fade-in-up" style="animation-delay:0.3s">
            <i class="bi bi-crosshair card-icon"></i>
            <div class="card-value"><?= e((string)$activeEngagements) ?></div>
            <div class="card-label">Active Engagements</div>
        </div>
    </div>
</div>

<!-- ── Charts ─────────────────────────────────────────────────────── -->
<div class="row g-4 mb-4">
    <!-- Severity Distribution (Doughnut) -->
    <div class="col-md-6 col-xl-3">
        <div class="glass-card chart-container fade-in-up" style="animation-delay:0.1s">
            <h6 class="text-muted mb-3"><i class="bi bi-pie-chart text-cyan"></i> Severity Distribution</h6>
            <canvas id="severityChart" height="260"></canvas>
        </div>
    </div>
    <!-- Open Vulns by Criticality (Bar) -->
    <div class="col-md-6 col-xl-3">
        <div class="glass-card chart-container fade-in-up" style="animation-delay:0.15s">
            <h6 class="text-muted mb-3"><i class="bi bi-bar-chart text-electric"></i> Vulns by Asset Criticality</h6>
            <canvas id="criticalityChart" height="260"></canvas>
        </div>
    </div>
    <!-- Top 5 Attacked Assets (Horizontal Bar) -->
    <div class="col-md-6 col-xl-3">
        <div class="glass-card chart-container fade-in-up" style="animation-delay:0.2s">
            <h6 class="text-muted mb-3"><i class="bi bi-bullseye text-magenta"></i> Top Attacked Assets</h6>
            <canvas id="attackedChart" height="260"></canvas>
        </div>
    </div>
    <!-- Incidents Over Time (Line) -->
    <div class="col-md-6 col-xl-3">
        <div class="glass-card chart-container fade-in-up" style="animation-delay:0.25s">
            <h6 class="text-muted mb-3"><i class="bi bi-graph-up text-cyan"></i> Incidents Over Time</h6>
            <canvas id="incidentsChart" height="260"></canvas>
        </div>
    </div>
</div>

<!-- ── Attention Feed ─────────────────────────────────────────────── -->
<div class="row g-4 mb-2">
    <div class="col-12">
        <div class="glass-card fade-in-up" style="animation-delay:0.3s">
            <div class="p-3 pb-0">
                <h6 class="text-muted mb-0"><i class="bi bi-bell text-cyan"></i> Attention Feed</h6>
            </div>
            <?php if (empty($feedItems)): ?>
                <div class="empty-state">
                    <i class="bi bi-check-circle d-block"></i>
                    <p>All clear — no new items require attention.</p>
                </div>
            <?php else: ?>
                <?php foreach ($feedItems as $item): ?>
                    <div class="feed-item">
                        <?php if ($item['itemType'] === 'Vulnerability'): ?>
                            <div class="feed-icon vuln"><i class="bi bi-bug"></i></div>
                        <?php else: ?>
                            <div class="feed-icon incident"><i class="bi bi-exclamation-triangle"></i></div>
                        <?php endif; ?>
                        <div class="flex-grow-1">
                            <div class="d-flex justify-content-between align-items-start">
                                <div>
                                    <span class="badge bg-secondary me-1"><?= e($item['itemType']) ?></span>
                                    <span class="fw-500"><?= e($item['itemTitle']) ?></span>
                                </div>
                                <small class="text-muted text-nowrap ms-2"><?= e($item['dateRaised'] ?? '') ?></small>
                            </div>
                            <div class="mt-1">
                                <?= severityBadge($item['priority']) ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Chart initialization (must be after canvas elements, before footer closes body) -->
<script>
document.addEventListener('DOMContentLoaded', function() {
    // Severity Doughnut
    createDoughnutChart('severityChart',
        <?= json_encode($sevLabels) ?>,
        <?= json_encode($sevData) ?>,
        [chartColors.critical, chartColors.high, chartColors.medium, chartColors.low]
    );

    // Criticality Bar
    createBarChart('criticalityChart',
        <?= json_encode($critLabels) ?>,
        <?= json_encode($critData) ?>,
        chartColors.blue
    );

    // Top Attacked Horizontal Bar
    createHorizontalBarChart('attackedChart',
        <?= json_encode($atkLabels) ?>,
        <?= json_encode($atkData) ?>,
        chartColors.magenta
    );

    // Incidents Line
    createLineChart('incidentsChart',
        <?= json_encode($incLabels) ?>,
        <?= json_encode($incData) ?>,
        chartColors.cyan
    );
});
</script>

<?php require __DIR__ . '/../includes/footer.php'; ?>
