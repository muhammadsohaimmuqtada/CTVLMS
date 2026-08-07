<?php
/**
 * CTVLMS — Post-remediation verification.
 */

require_once __DIR__ . '/exposure.php';

/**
 * Verify one Remediated exposure against fresh/current inventory.
 * Returns true only when the current product/version no longer matches any
 * vulnerable NVD applicability rule for that CVE.
 */
function verifyRemediatedExposure(PDO $db, int $exposureID): bool
{
    $stmt = $db->prepare(
        "SELECT e.*, j.remediationID, j.completedAt AS jobCompletedAt,
                av.assetVulnID
         FROM exposure_matches e
         JOIN remediation_jobs j ON j.exposureID = e.exposureID AND j.status = 'Succeeded'
         JOIN asset_vulnerabilities av ON av.assetID = e.assetID AND av.vulnID = e.vulnID
         WHERE e.exposureID = :id
           AND e.status IN ('Remediated','Verification_Failed')
         ORDER BY j.completedAt DESC
         LIMIT 1"
    );
    $stmt->execute([':id' => $exposureID]);
    $exposure = $stmt->fetch();
    if (!$exposure || empty($exposure['remediationID'])) {
        return false;
    }

    $inventory = null;
    if (!empty($exposure['softwareID'])) {
        $inv = $db->prepare('SELECT cpe, version, lastSeen FROM asset_software WHERE softwareID = :id');
        $inv->execute([':id' => $exposure['softwareID']]);
        $inventory = $inv->fetch();
    } elseif (!empty($exposure['serviceID'])) {
        $inv = $db->prepare('SELECT cpe, version, lastSeen FROM asset_services WHERE serviceID = :id');
        $inv->execute([':id' => $exposure['serviceID']]);
        $inventory = $inv->fetch();
    }

    if (!$inventory || empty($inventory['cpe']) || empty($inventory['lastSeen'])) {
        return false;
    }

    // Verification evidence must be at least as new as the remediation job.
    if (!empty($exposure['jobCompletedAt']) && strtotime($inventory['lastSeen']) < strtotime($exposure['jobCompletedAt'])) {
        return false;
    }

    $rules = $db->prepare(
        'SELECT * FROM vulnerability_cpe_matches WHERE vulnID = :vuln AND vulnerable = 1'
    );
    $rules->execute([':vuln' => $exposure['vulnID']]);

    $stillAffected = [];
    foreach ($rules->fetchAll() as $rule) {
        $match = evaluateCpeRule($inventory['cpe'], $rule, $inventory['version'] ?? null);
        if ($match !== null) {
            $stillAffected[] = [
                'criteria' => $rule['criteria'],
                'match_type' => $match['type'],
                'confidence' => $match['confidence'],
                'status' => $match['status'],
            ];
        }
    }

    if ($stillAffected) {
        $evidence = json_encode([
            'result' => 'still_affected',
            'observed_cpe' => $inventory['cpe'],
            'observed_version' => $inventory['version'],
            'matches' => $stillAffected,
            'verified_at' => gmdate(DATE_ATOM),
        ], JSON_UNESCAPED_SLASHES);

        $fail = $db->prepare(
            "UPDATE exposure_matches
             SET status = 'Verification_Failed', evidence = :evidence, lastEvaluated = CURRENT_TIMESTAMP
             WHERE exposureID = :id"
        );
        $fail->execute([':evidence' => $evidence, ':id' => $exposureID]);
        $life = $db->prepare(
            "UPDATE asset_vulnerabilities
             SET status = 'Remediation_In_Progress', closedDate = NULL
             WHERE assetVulnID = :id AND status = 'Remediated'"
        );
        $life->execute([':id' => $exposure['assetVulnID']]);
        logAction('VERIFY_FAILED', 'exposure_matches', $exposureID, 'Post-patch inventory still matches vulnerable applicability');
        return false;
    }

    $evidence = json_encode([
        'result' => 'not_affected_after_remediation',
        'observed_cpe' => $inventory['cpe'],
        'observed_version' => $inventory['version'],
        'inventory_last_seen' => $inventory['lastSeen'],
        'verified_at' => gmdate(DATE_ATOM),
    ], JSON_UNESCAPED_SLASHES);

    $db->beginTransaction();
    try {
        $verification = $db->prepare(
            "INSERT INTO remediation_verifications
                (remediationID, verifierType, verifiedByUserID, evidence)
             VALUES (:remediation, 'Automated', NULL, :evidence)
             ON DUPLICATE KEY UPDATE
                verifierType = 'Automated', verifiedByUserID = NULL,
                evidence = VALUES(evidence), verifiedAt = CURRENT_TIMESTAMP"
        );
        $verification->execute([
            ':remediation' => $exposure['remediationID'],
            ':evidence' => $evidence,
        ]);

        $closeExposure = $db->prepare(
            "UPDATE exposure_matches
             SET status = 'Verified_Closed', evidence = :evidence, lastEvaluated = CURRENT_TIMESTAMP
             WHERE exposureID = :id"
        );
        $closeExposure->execute([':evidence' => $evidence, ':id' => $exposureID]);

        $closeLifecycle = $db->prepare(
            "UPDATE asset_vulnerabilities
             SET status = 'Verified_Closed', closedDate = CURDATE()
             WHERE assetVulnID = :id AND status = 'Remediated'"
        );
        $closeLifecycle->execute([':id' => $exposure['assetVulnID']]);

        logAction('AUTO_VERIFY', 'remediations', (int)$exposure['remediationID'], 'Post-patch applicability check verified exposure closed');
        logAction('STATUS_CHANGE', 'asset_vulnerabilities', (int)$exposure['assetVulnID'], 'Status: Remediated → Verified_Closed after automated verification');
        $db->commit();
        return true;
    } catch (Throwable $ex) {
        if ($db->inTransaction()) $db->rollBack();
        throw $ex;
    }
}
