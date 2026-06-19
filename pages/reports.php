<?php
/**
 * CTVLMS — Reports (12 Query Bank)
 */

$pageTitle = 'SQL Reports';
$db = getDB();

// ── Define All 12 Queries ────────────────────────────────────────────

$queries = [
    [
        'title' => '1. INNER JOIN — Assets with Open Vulnerabilities',
        'sql'   => "SELECT a.assetName, a.criticality, v.title, v.severity, av.status
FROM asset_vulnerabilities av
INNER JOIN assets a ON av.assetID = a.assetID
INNER JOIN vulnerabilities v ON av.vulnID = v.vulnID
WHERE av.status NOT IN ('Remediated','Verified_Closed','Risk_Accepted')",
    ],
    [
        'title' => '2. LEFT JOIN — All Assets with Vulnerability Counts',
        'sql'   => "SELECT a.assetName, a.assetType, COUNT(av.assetVulnID) AS openVulnCount
FROM assets a
LEFT JOIN asset_vulnerabilities av ON a.assetID = av.assetID
  AND av.status NOT IN ('Remediated','Verified_Closed')
GROUP BY a.assetID, a.assetName, a.assetType
ORDER BY openVulnCount DESC",
    ],
    [
        'title' => '3. Multi-Table JOIN — Incident Detail Report',
        'sql'   => "SELECT i.title AS incidentTitle, a.assetName, ta.actorName AS attributedActor,
       v.cveID, v.title AS vulnExploited, u.fullName AS handledBy, i.status
FROM incidents i
JOIN assets a ON i.assetID = a.assetID
LEFT JOIN threat_actors ta ON i.actorID = ta.actorID
LEFT JOIN vulnerabilities v ON i.relatedVulnID = v.vulnID
LEFT JOIN users u ON i.assignedToUserID = u.userID
ORDER BY i.detectedDate DESC",
    ],
    [
        'title' => '4. HAVING — High-Risk Assets (≥3 Unresolved Vulns)',
        'sql'   => "SELECT a.assetName, a.criticality, COUNT(*) AS unresolvedCount
FROM assets a
JOIN asset_vulnerabilities av ON a.assetID = av.assetID
WHERE av.status NOT IN ('Remediated','Verified_Closed','Risk_Accepted')
GROUP BY a.assetID, a.assetName, a.criticality
HAVING COUNT(*) >= 3
ORDER BY unresolvedCount DESC",
    ],
    [
        'title' => '5. Subquery — Vulnerabilities Above Average CVSS',
        'sql'   => "SELECT cveID, title, cvssScore, severity
FROM vulnerabilities
WHERE cvssScore > (SELECT AVG(cvssScore) FROM vulnerabilities)
ORDER BY cvssScore DESC",
    ],
    [
        'title' => '6. IN + Subquery — Assets in Active Engagements',
        'sql'   => "SELECT assetName, assetType, criticality
FROM assets
WHERE assetID IN (
    SELECT ea.assetID
    FROM engagement_assets ea
    JOIN engagements e ON ea.engagementID = e.engagementID
    WHERE e.status = 'In_Progress'
)",
    ],
    [
        'title' => '7. Multi-JOIN — High/Critical Engagement Findings',
        'sql'   => "SELECT e.engagementName, a.assetName, f.title AS findingTitle,
       f.riskRating, f.exploitedSuccessfully, u.fullName AS discoveredBy
FROM findings f
JOIN engagements e ON f.engagementID = e.engagementID
JOIN assets a ON f.assetID = a.assetID
LEFT JOIN users u ON f.discoveredByUserID = u.userID
WHERE f.riskRating IN ('High','Critical')
ORDER BY e.startDate DESC",
    ],
    [
        'title' => '8. Aggregate — Average Days to Remediate by Criticality',
        'sql'   => "SELECT a.criticality,
       ROUND(AVG(DATEDIFF(r.completedDate, av.discoveredDate)), 1) AS avgDaysToFix
FROM remediations r
JOIN asset_vulnerabilities av ON r.assetVulnID = av.assetVulnID
JOIN assets a ON av.assetID = a.assetID
WHERE r.completedDate IS NOT NULL
GROUP BY a.criticality",
    ],
    [
        'title' => '9. RIGHT JOIN — All IOCs with Threat Actor Attribution',
        'sql'   => "SELECT ioc.iocValue, ioc.iocType, ioc.mitreTechnique, ta.actorName
FROM threat_actors ta
RIGHT JOIN indicators_of_compromise ioc ON ta.actorID = ioc.actorID",
    ],
    [
        'title' => '10. UNION — Attention Feed (New Vulns + Open Incidents)',
        'sql'   => "SELECT 'Vulnerability' AS itemType, v.title AS itemTitle, v.severity AS priority,
       av.discoveredDate AS dateRaised
FROM asset_vulnerabilities av
JOIN vulnerabilities v ON av.vulnID = v.vulnID
WHERE av.status = 'Discovered'
UNION
SELECT 'Incident' AS itemType, i.title AS itemTitle, i.severity AS priority,
       DATE(i.detectedDate) AS dateRaised
FROM incidents i
WHERE i.status = 'Open'
ORDER BY priority DESC, dateRaised ASC",
    ],
    [
        'title' => '11. VIEW — Open Vulnerability Lifecycle',
        'sql'   => "SELECT * FROM vw_open_lifecycle",
    ],
    [
        'title' => '12. Aggregate + LIMIT — Top 5 Most Attacked Assets',
        'sql'   => "SELECT a.assetName, COUNT(i.incidentID) AS incidentCount
FROM assets a
JOIN incidents i ON a.assetID = i.assetID
GROUP BY a.assetID, a.assetName
ORDER BY incidentCount DESC
LIMIT 5",
    ],
];

require __DIR__ . '/../includes/header.php';
?>

<div class="page-header">
    <h2><i class="bi bi-file-earmark-bar-graph"></i> SQL Query Reports</h2>
    <span class="text-muted small"><?= e(count($queries)) ?> queries from the project query bank</span>
</div>

<div class="accordion" id="queryAccordion">
    <?php foreach ($queries as $idx => $q): ?>
        <?php
        $num       = $idx + 1;
        $collapseId = 'query' . $num;
        $isFirst   = ($idx === 0);

        // Execute query with error handling
        $rows  = [];
        $error = '';
        try {
            $stmt = $db->query($q['sql']);
            $rows = $stmt->fetchAll();
        } catch (PDOException $ex) {
            $error = $ex->getMessage();
        }
        ?>
        <div class="query-card accordion-item">
            <h2 class="accordion-header" id="heading<?= $num ?>">
                <button class="accordion-button <?= $isFirst ? '' : 'collapsed' ?>"
                        type="button"
                        data-bs-toggle="collapse"
                        data-bs-target="#<?= $collapseId ?>"
                        aria-expanded="<?= $isFirst ? 'true' : 'false' ?>"
                        aria-controls="<?= $collapseId ?>">
                    <i class="bi bi-database me-2 text-cyan"></i>
                    <?= e($q['title']) ?>
                    <span class="badge bg-secondary ms-auto me-2"><?= e((string)count($rows)) ?> rows</span>
                </button>
            </h2>
            <div id="<?= $collapseId ?>"
                 class="accordion-collapse collapse <?= $isFirst ? 'show' : '' ?>"
                 aria-labelledby="heading<?= $num ?>"
                 data-bs-parent="#queryAccordion">
                <div class="accordion-body">
                    <!-- SQL Query Display -->
                    <pre class="query-sql"><code><?= e($q['sql']) ?></code></pre>

                    <?php if ($error): ?>
                        <div class="alert alert-danger">
                            <i class="bi bi-exclamation-octagon me-1"></i>
                            <strong>Query Error:</strong> <?= e($error) ?>
                        </div>
                    <?php elseif (empty($rows)): ?>
                        <div class="empty-state">
                            <i class="bi bi-inbox d-block"></i>
                            <p>No results returned.</p>
                        </div>
                    <?php else: ?>
                        <div class="table-responsive">
                            <table class="table table-dark-custom table-hover mb-0">
                                <thead>
                                    <tr>
                                        <?php foreach (array_keys($rows[0]) as $col): ?>
                                            <th><?= e($col) ?></th>
                                        <?php endforeach; ?>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($rows as $row): ?>
                                        <tr>
                                            <?php foreach ($row as $key => $val): ?>
                                                <td>
                                                    <?php
                                                    // Apply formatting for known columns
                                                    if (in_array($key, ['severity', 'priority', 'riskRating', 'criticality'])) {
                                                        echo severityBadge($val);
                                                    } elseif ($key === 'status') {
                                                        echo statusBadge($val);
                                                    } elseif ($key === 'cveID') {
                                                        echo '<span class="font-mono">' . e($val) . '</span>';
                                                    } elseif ($key === 'exploitedSuccessfully') {
                                                        if ($val) {
                                                            echo '<span class="badge badge-critical">Yes</span>';
                                                        } else {
                                                            echo '<span class="badge badge-low">No</span>';
                                                        }
                                                    } elseif ($key === 'iocValue') {
                                                        echo '<span class="font-mono">' . e($val) . '</span>';
                                                    } else {
                                                        echo e((string)($val ?? '—'));
                                                    }
                                                    ?>
                                                </td>
                                            <?php endforeach; ?>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    <?php endforeach; ?>
</div>

<?php require __DIR__ . '/../includes/footer.php'; ?>
