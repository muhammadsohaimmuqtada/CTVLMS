<?php
/**
 * CTVLMS — Asset-aware exposure correlation.
 *
 * NVD CPE applicability is correlated with observed service/software CPEs.
 * Correlation produces evidence-backed exposure records and lifecycle mappings;
 * it does not blindly treat every CVE as applicable to every asset.
 */

function parseCpe23(?string $cpe): ?array
{
    if (!$cpe || !str_starts_with($cpe, 'cpe:2.3:')) {
        return null;
    }

    $parts = preg_split('/(?<!\\\\):/', $cpe);
    if (!$parts || count($parts) < 6) {
        return null;
    }

    $decode = static function (string $value): string {
        return str_replace(['\\:', '\\!', '\\?', '\\\\'], [':', '!', '?', '\\'], $value);
    };

    return [
        'part'    => $decode($parts[2]),
        'vendor'  => strtolower($decode($parts[3])),
        'product' => strtolower($decode($parts[4])),
        'version' => $decode($parts[5]),
    ];
}

function cpeBaseKey(array $cpe): string
{
    return $cpe['part'] . '|' . $cpe['vendor'] . '|' . $cpe['product'];
}

function cpeVersionKnown(?string $version): bool
{
    return $version !== null && $version !== '' && $version !== '*' && $version !== '-';
}

function versionWithinNvdRange(string $version, array $rule): bool
{
    if (!empty($rule['versionStartIncluding']) && version_compare($version, $rule['versionStartIncluding'], '<')) return false;
    if (!empty($rule['versionStartExcluding']) && version_compare($version, $rule['versionStartExcluding'], '<=')) return false;
    if (!empty($rule['versionEndIncluding']) && version_compare($version, $rule['versionEndIncluding'], '>')) return false;
    if (!empty($rule['versionEndExcluding']) && version_compare($version, $rule['versionEndExcluding'], '>=')) return false;
    return true;
}

/**
 * Evaluate one inventory CPE against one NVD CPE rule.
 *
 * $observedVersionOverride is used for package inventory where the CPE may
 * intentionally keep a wildcard version while the package manager reports the
 * authoritative installed version separately.
 */
function evaluateCpeRule(string $inventoryCpe, array $rule, ?string $observedVersionOverride = null): ?array
{
    $observed = parseCpe23($inventoryCpe);
    $criteria = parseCpe23($rule['criteria'] ?? null);
    if (!$observed || !$criteria || cpeBaseKey($observed) !== cpeBaseKey($criteria)) {
        return null;
    }

    if (empty($rule['vulnerable'])) {
        return null;
    }

    $observedVersion = cpeVersionKnown($observedVersionOverride) ? $observedVersionOverride : $observed['version'];
    $criteriaVersion = $criteria['version'];
    $hasRange = !empty($rule['versionStartIncluding']) || !empty($rule['versionStartExcluding']) ||
                !empty($rule['versionEndIncluding']) || !empty($rule['versionEndExcluding']);
    $complex = !empty($rule['configurationComplex']);

    $result = null;
    if (cpeVersionKnown($criteriaVersion)) {
        if (!cpeVersionKnown($observedVersion) || version_compare($observedVersion, $criteriaVersion, '!=')) return null;
        $result = ['type' => 'CPE_Exact', 'confidence' => 0.995, 'status' => 'Confirmed'];
    } elseif ($hasRange) {
        if (!cpeVersionKnown($observedVersion)) {
            $result = ['type' => 'CPE_Potential', 'confidence' => 0.600, 'status' => 'Potential'];
        } else {
            if (!versionWithinNvdRange($observedVersion, $rule)) return null;
            $result = ['type' => 'CPE_Range', 'confidence' => 0.960, 'status' => 'Confirmed'];
        }
    } elseif (cpeVersionKnown($observedVersion)) {
        $result = ['type' => 'CPE_Exact', 'confidence' => 0.950, 'status' => 'Confirmed'];
    } else {
        $result = ['type' => 'CPE_Potential', 'confidence' => 0.650, 'status' => 'Potential'];
    }

    if ($complex) {
        // Additional platform/AND/negation conditions must be proven before an
        // automated remediation decision can be made.
        $result['type'] = 'CPE_Potential';
        $result['confidence'] = min($result['confidence'], 0.700);
        $result['status'] = 'Potential';
    }

    return $result;
}

function loadCpeInventory(PDO $db, ?int $assetID = null): array
{
    $filter = $assetID !== null ? ' WHERE assetID = :assetID AND cpe IS NOT NULL AND cpe <> \'\'' : ' WHERE cpe IS NOT NULL AND cpe <> \'\'';
    $params = $assetID !== null ? [':assetID' => $assetID] : [];

    $software = $db->prepare(
        'SELECT softwareID AS sourceID, assetID, cpe, version, packageName, packageManager
         FROM asset_software' . $filter
    );
    $software->execute($params);

    $services = $db->prepare(
        'SELECT serviceID AS sourceID, assetID, cpe, version, NULL AS packageName, NULL AS packageManager
         FROM asset_services' . $filter
    );
    $services->execute($params);

    $inventory = [];
    foreach ($software->fetchAll() as $row) {
        $row['sourceType'] = 'software';
        $inventory[] = $row;
    }
    foreach ($services->fetchAll() as $row) {
        $row['sourceType'] = 'service';
        $inventory[] = $row;
    }
    return $inventory;
}

function evaluateExposureInventory(PDO $db, ?int $assetID = null): array
{
    $rules = $db->query(
        'SELECT vc.*, v.cveID, v.severity
         FROM vulnerability_cpe_matches vc
         JOIN vulnerabilities v ON v.vulnID = vc.vulnID
         WHERE vc.vulnerable = 1'
    )->fetchAll();

    $rulesByBase = [];
    foreach ($rules as $rule) {
        $parsed = parseCpe23($rule['criteria']);
        if (!$parsed) continue;
        $rulesByBase[cpeBaseKey($parsed)][] = $rule;
    }

    $inventory = loadCpeInventory($db, $assetID);
    $matched = 0;
    $potential = 0;
    $confirmed = 0;

    $upsert = $db->prepare(
        "INSERT INTO exposure_matches
            (matchKey, assetID, vulnID, softwareID, serviceID, matchType, confidence, status, evidence)
         VALUES
            (:key, :asset, :vuln, :software, :service, :type, :confidence, :status, :evidence)
         ON DUPLICATE KEY UPDATE
            confidence = VALUES(confidence),
            matchType = VALUES(matchType),
            evidence = VALUES(evidence),
            lastEvaluated = CURRENT_TIMESTAMP,
            status = CASE
                WHEN exposure_matches.status = 'Not_Affected' THEN 'Not_Affected'
                WHEN exposure_matches.status = 'Verified_Closed' THEN 'Verification_Failed'
                WHEN exposure_matches.status IN ('Remediation_Queued','Remediating') THEN exposure_matches.status
                ELSE VALUES(status)
            END"
    );

    $map = $db->prepare(
        "INSERT IGNORE INTO asset_vulnerabilities
            (assetID, vulnID, status, discoveredDate, notes)
         VALUES (:asset, :vuln, 'Discovered', CURDATE(), :notes)"
    );

    foreach ($inventory as $item) {
        $parsed = parseCpe23($item['cpe']);
        if (!$parsed) continue;
        $candidateRules = $rulesByBase[cpeBaseKey($parsed)] ?? [];

        foreach ($candidateRules as $rule) {
            $result = evaluateCpeRule($item['cpe'], $rule, $item['version'] ?? null);
            if ($result === null) continue;

            $key = hash('sha256', implode('|', [
                $item['assetID'],
                $rule['vulnID'],
                $item['sourceType'],
                $item['sourceID'],
                $rule['criteria'],
            ]));

            $evidence = json_encode([
                'observed_cpe' => $item['cpe'],
                'observed_version' => $item['version'],
                'nvd_criteria' => $rule['criteria'],
                'configuration_complex' => (bool)$rule['configurationComplex'],
                'version_start_including' => $rule['versionStartIncluding'],
                'version_start_excluding' => $rule['versionStartExcluding'],
                'version_end_including' => $rule['versionEndIncluding'],
                'version_end_excluding' => $rule['versionEndExcluding'],
                'source_type' => $item['sourceType'],
                'source_id' => (int)$item['sourceID'],
                'cve' => $rule['cveID'],
            ], JSON_UNESCAPED_SLASHES);

            $upsert->execute([
                ':key' => $key,
                ':asset' => (int)$item['assetID'],
                ':vuln' => (int)$rule['vulnID'],
                ':software' => $item['sourceType'] === 'software' ? (int)$item['sourceID'] : null,
                ':service' => $item['sourceType'] === 'service' ? (int)$item['sourceID'] : null,
                ':type' => $result['type'],
                ':confidence' => $result['confidence'],
                ':status' => $result['status'],
                ':evidence' => $evidence,
            ]);

            $map->execute([
                ':asset' => (int)$item['assetID'],
                ':vuln' => (int)$rule['vulnID'],
                ':notes' => 'Automatically discovered by CTVLMS exposure correlation.',
            ]);

            $matched++;
            if ($result['status'] === 'Confirmed') $confirmed++;
            else $potential++;
        }
    }

    return [
        'inventory_items' => count($inventory),
        'matches' => $matched,
        'confirmed' => $confirmed,
        'potential' => $potential,
    ];
}

function assetHasValidBackupEvidence(PDO $db, int $assetID): bool
{
    $stmt = $db->prepare(
        'SELECT 1
         FROM asset_backup_evidence
         WHERE assetID = :asset
           AND (validUntil IS NULL OR validUntil >= CURRENT_TIMESTAMP)
         LIMIT 1'
    );
    $stmt->execute([':asset' => $assetID]);
    return (bool)$stmt->fetchColumn();
}

/**
 * Turn confirmed software exposures into package-specific remediation jobs.
 * Auto mode is blocked when its policy requires backup evidence and none is
 * valid. Approval mode may still create an Awaiting_Approval job for review.
 */
function queueEligibleRemediationJobs(PDO $db, ?int $assetID = null): int
{
    $sql = "SELECT e.exposureID, e.assetID, e.softwareID, s.packageManager, s.packageName, s.version,
                   p.mode, p.requireVerifiedBackup
            FROM exposure_matches e
            JOIN asset_software s ON s.softwareID = e.softwareID
            JOIN asset_patch_policies p ON p.assetID = e.assetID
            WHERE e.status = 'Confirmed'
              AND s.packageName IS NOT NULL
              AND s.packageName <> ''
              AND s.packageManager IN ('apt','dnf','yum','apk')
              AND p.mode <> 'Disabled'";
    $params = [];
    if ($assetID !== null) {
        $sql .= ' AND e.assetID = :assetID';
        $params[':assetID'] = $assetID;
    }

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    $exists = $db->prepare(
        "SELECT 1 FROM remediation_jobs
         WHERE exposureID = :exposure
           AND status IN ('Queued','Awaiting_Approval','Approved','Running')
         LIMIT 1"
    );
    $insert = $db->prepare(
        'INSERT INTO remediation_jobs
            (exposureID, assetID, softwareID, packageManager, packageName, fromVersion, status)
         VALUES (:exposure, :asset, :software, :manager, :package, :version, :status)'
    );
    $mark = $db->prepare("UPDATE exposure_matches SET status = 'Remediation_Queued' WHERE exposureID = :id");

    $queued = 0;
    foreach ($rows as $row) {
        $exists->execute([':exposure' => $row['exposureID']]);
        if ($exists->fetchColumn()) continue;

        if ($row['mode'] === 'Auto' && (bool)$row['requireVerifiedBackup'] && !assetHasValidBackupEvidence($db, (int)$row['assetID'])) {
            // Leave exposure Confirmed. Once backup evidence is registered the
            // next cycle can safely create the automatic job.
            continue;
        }

        $status = $row['mode'] === 'Auto' ? 'Queued' : 'Awaiting_Approval';
        $insert->execute([
            ':exposure' => $row['exposureID'],
            ':asset' => $row['assetID'],
            ':software' => $row['softwareID'],
            ':manager' => $row['packageManager'],
            ':package' => $row['packageName'],
            ':version' => $row['version'],
            ':status' => $status,
        ]);
        $mark->execute([':id' => $row['exposureID']]);
        $queued++;
    }

    return $queued;
}
