-- =====================================================================
-- CTVLMS — Sample Query Bank
-- Demonstrates: INNER JOIN, LEFT JOIN, multi-table JOIN, subqueries,
-- aggregation, GROUP BY/HAVING, views — aligned with course topics.
-- =====================================================================

-- 1. INNER JOIN: list every asset with an open vulnerability, with severity
SELECT a.assetName, a.criticality, v.title, v.severity, av.status
FROM asset_vulnerabilities av
INNER JOIN assets a ON av.assetID = a.assetID
INNER JOIN vulnerabilities v ON av.vulnID = v.vulnID
WHERE av.status NOT IN ('Remediated','Verified_Closed','Risk_Accepted');

-- 2. LEFT JOIN: list all assets, even those with zero vulnerabilities found
SELECT a.assetName, a.assetType, COUNT(av.assetVulnID) AS openVulnCount
FROM assets a
LEFT JOIN asset_vulnerabilities av ON a.assetID = av.assetID
    AND av.status NOT IN ('Remediated','Verified_Closed')
GROUP BY a.assetID, a.assetName, a.assetType
ORDER BY openVulnCount DESC;

-- 3. Multi-table JOIN: full incident report (asset + actor + vuln + handler)
SELECT i.title AS incidentTitle, a.assetName, ta.actorName AS attributedActor,
       v.cveID, v.title AS vulnExploited, u.fullName AS handledBy, i.status
FROM incidents i
JOIN assets a ON i.assetID = a.assetID
LEFT JOIN threat_actors ta ON i.actorID = ta.actorID
LEFT JOIN vulnerabilities v ON i.relatedVulnID = v.vulnID
LEFT JOIN users u ON i.assignedToUserID = u.userID
ORDER BY i.detectedDate DESC;

-- 4. JOIN + GROUP BY + HAVING: critical assets with 3+ unresolved vulns
SELECT a.assetName, a.criticality, COUNT(*) AS unresolvedCount
FROM assets a
JOIN asset_vulnerabilities av ON a.assetID = av.assetID
WHERE av.status NOT IN ('Remediated','Verified_Closed','Risk_Accepted')
GROUP BY a.assetID, a.assetName, a.criticality
HAVING COUNT(*) >= 3
ORDER BY unresolvedCount DESC;

-- 5. Correlated subquery: vulnerabilities with above-average CVSS score
SELECT cveID, title, cvssScore, severity
FROM vulnerabilities
WHERE cvssScore > (SELECT AVG(cvssScore) FROM vulnerabilities)
ORDER BY cvssScore DESC;

-- 6. Subquery with IN: assets currently in scope of an active engagement
SELECT assetName, assetType, criticality
FROM assets
WHERE assetID IN (
    SELECT ea.assetID
    FROM engagement_assets ea
    JOIN engagements e ON ea.engagementID = e.engagementID
    WHERE e.status = 'In_Progress'
);

-- 7. Three-way JOIN: red team findings with engagement + asset + discoverer
SELECT e.engagementName, a.assetName, f.title AS findingTitle,
       f.riskRating, f.exploitedSuccessfully, u.fullName AS discoveredBy
FROM findings f
JOIN engagements e ON f.engagementID = e.engagementID
JOIN assets a ON f.assetID = a.assetID
LEFT JOIN users u ON f.discoveredByUserID = u.userID
WHERE f.riskRating IN ('High','Critical')
ORDER BY e.startDate DESC;

-- 8. Aggregate: mean time-to-remediate (in days) per asset criticality tier
SELECT a.criticality,
       ROUND(AVG(DATEDIFF(r.completedDate, av.discoveredDate)), 1) AS avgDaysToFix
FROM remediations r
JOIN asset_vulnerabilities av ON r.assetVulnID = av.assetVulnID
JOIN assets a ON av.assetID = a.assetID
WHERE r.completedDate IS NOT NULL
GROUP BY a.criticality;

-- 9. RIGHT JOIN example: every IOC and its attributed actor (even if actor unknown)
SELECT ioc.iocValue, ioc.iocType, ioc.mitreTechnique, ta.actorName
FROM threat_actors ta
RIGHT JOIN indicators_of_compromise ioc ON ta.actorID = ioc.actorID;

-- 10. UNION: single combined "things needing attention" feed for a dashboard
SELECT 'Vulnerability' AS itemType, v.title AS itemTitle, v.severity AS priority, av.discoveredDate AS dateRaised
FROM asset_vulnerabilities av
JOIN vulnerabilities v ON av.vulnID = v.vulnID
WHERE av.status = 'Discovered'
UNION
SELECT 'Incident' AS itemType, i.title AS itemTitle, i.severity AS priority, DATE(i.detectedDate) AS dateRaised
FROM incidents i
WHERE i.status = 'Open'
ORDER BY priority DESC, dateRaised ASC;

-- 11. View: open lifecycle dashboard (commonly demoed in lab presentations)
CREATE OR REPLACE VIEW vw_open_lifecycle AS
SELECT a.assetName, v.cveID, v.severity, av.status, av.discoveredDate, av.dueDate,
       DATEDIFF(CURDATE(), av.discoveredDate) AS daysOpen
FROM asset_vulnerabilities av
JOIN assets a ON av.assetID = a.assetID
JOIN vulnerabilities v ON av.vulnID = v.vulnID
WHERE av.status NOT IN ('Remediated','Verified_Closed');

-- 12. Self-contained: top 5 most "attacked" assets by incident count
SELECT a.assetName, COUNT(i.incidentID) AS incidentCount
FROM assets a
JOIN incidents i ON a.assetID = i.assetID
GROUP BY a.assetID, a.assetName
ORDER BY incidentCount DESC
LIMIT 5;
