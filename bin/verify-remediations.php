#!/usr/bin/env php
<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/verification.php';

$db = getDB();
$rows = $db->query(
    "SELECT DISTINCT e.exposureID
     FROM exposure_matches e
     JOIN remediation_jobs j ON j.exposureID = e.exposureID AND j.status = 'Succeeded'
     WHERE e.status IN ('Remediated','Verification_Failed')
     ORDER BY e.lastEvaluated ASC"
)->fetchAll(PDO::FETCH_COLUMN);

$verified = 0;
$pending = 0;
foreach ($rows as $exposureID) {
    try {
        if (verifyRemediatedExposure($db, (int)$exposureID)) $verified++;
        else $pending++;
    } catch (Throwable $ex) {
        $pending++;
        fwrite(STDERR, "Exposure #{$exposureID}: {$ex->getMessage()}\n");
    }
}

echo json_encode([
    'checked' => count($rows),
    'verified_closed' => $verified,
    'pending_or_failed' => $pending,
], JSON_PRETTY_PRINT) . PHP_EOL;
