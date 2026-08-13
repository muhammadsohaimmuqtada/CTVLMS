<?php
/**
 * Scalable distribution-package applicability evaluation.
 *
 * Candidate-only cross-distribution intelligence is summarized per package and
 * is never materialized as exposure_matches. Only authoritative provider/suite
 * matches can create package advisory exposure rows.
 */
require_once __DIR__ . '/debian_version.php';
require_once __DIR__ . '/package_candidate_policy.php';

function packageDistributionContextV2(PDO $db, int $assetID): array
{
    $stmt = $db->prepare(
        "SELECT factKey,factValue FROM asset_facts
         WHERE assetID=:asset AND factKey IN ('os_id','distribution_suite')
         ORDER BY confidence DESC,lastSeen DESC"
    );
    $stmt->execute([':asset'=>$assetID]);
    $facts = [];
    foreach ($stmt->fetchAll() as $row) {
        if (!isset($facts[$row['factKey']])) $facts[$row['factKey']] = strtolower(trim((string)$row['factValue']));
    }
    return ['distribution'=>$facts['os_id'] ?? '', 'suite'=>$facts['distribution_suite'] ?? ''];
}

function packageFixedVersionApplicabilityV2(array $package, array $advisory, array $evidence): array
{
    $installed = trim((string)($package['sourceVersion'] ?: $package['binaryVersion']));
    $fixed = trim((string)$advisory['fixedVersion']);
    if ($installed === '' || $fixed === '') {
        return ['status'=>'Potential','confidence'=>0.500,'comparison_result'=>'unknown',
            'reason'=>'version_required_for_fixed_rule','evidence'=>$evidence];
    }
    $comparison = debianVersionCompare($installed, $fixed);
    return $comparison < 0
        ? ['status'=>'Confirmed','confidence'=>0.995,'comparison_result'=>'installed_lt_fixed',
            'reason'=>'installed_source_version_precedes_fixed_version','evidence'=>$evidence]
        : ['status'=>'Not_Affected','confidence'=>0.995,'comparison_result'=>$comparison === 0 ? 'installed_eq_fixed' : 'installed_gt_fixed',
            'reason'=>'installed_source_version_is_fixed','evidence'=>$evidence];
}

function authoritativePackageAdvisoryApplicability(array $package, array $advisory, array $distribution): array
{
    $baseEvidence = [
        'binary_package'=>$package['binaryPackage'],
        'source_package'=>$package['sourcePackage'],
        'installed_version'=>$package['binaryVersion'],
        'source_version'=>$package['sourceVersion'],
        'advisory'=>$advisory['advisoryIdentifier'],
        'cve'=>$advisory['cveID'],
        'distribution'=>$distribution['distribution'],
        'suite'=>$distribution['suite'],
        'advisory_distribution'=>$advisory['distribution'],
        'advisory_suite'=>$advisory['suite'],
        'fixed_version'=>$advisory['fixedVersion'],
        'provider'=>$advisory['provider'],
    ];

    if (packageCandidateDisposition($distribution, $advisory) !== 'authoritative') {
        throw new LogicException('authoritativePackageAdvisoryApplicability called for a non-authoritative rule');
    }
    if (!(bool)$package['identityAuthoritative'] || empty($package['sourcePackage'])) {
        return ['status'=>'Potential','confidence'=>0.450,'comparison_result'=>'not_compared',
            'reason'=>'package_identity_not_authoritative','evidence'=>$baseEvidence];
    }
    return match ($advisory['state']) {
        'Not_Affected' => ['status'=>'Not_Affected','confidence'=>0.995,'comparison_result'=>'not_affected',
            'reason'=>'provider_marks_suite_not_affected','evidence'=>$baseEvidence],
        'Vulnerable' => ['status'=>'Confirmed','confidence'=>0.995,'comparison_result'=>'provider_vulnerable',
            'reason'=>'provider_marks_suite_vulnerable','evidence'=>$baseEvidence],
        'Fixed' => packageFixedVersionApplicabilityV2($package, $advisory, $baseEvidence),
        default => ['status'=>'Potential','confidence'=>0.500,'comparison_result'=>'unknown',
            'reason'=>'provider_state_unknown','evidence'=>$baseEvidence],
    };
}

function loadActivePackagesForEvaluation(PDO $db, ?int $assetID = null): array
{
    $filter = $assetID === null ? '' : ' AND p.assetID=:asset';
    $stmt = $db->prepare(
        "SELECT p.*,s.softwareID
         FROM asset_package_inventory p
         JOIN asset_software s ON s.softwareID=p.softwareID AND s.isActive=1
         WHERE p.isActive=1{$filter}
         ORDER BY p.assetID,p.packageInventoryID"
    );
    $stmt->execute($assetID === null ? [] : [':asset'=>$assetID]);
    return $stmt->fetchAll();
}

function loadAdvisoriesForSourcePackages(PDO $db, array $sourcePackages): array
{
    $names = array_values(array_unique(array_filter(array_map(
        fn($name) => strtolower(trim((string)$name)),
        $sourcePackages
    ))));
    if (!$names) return [];

    $result = [];
    foreach (array_chunk($names, 250) as $chunk) {
        $placeholders = implode(',', array_fill(0, count($chunk), '?'));
        $stmt = $db->prepare(
            "SELECT a.*,v.vulnID
             FROM distribution_advisories a
             JOIN vulnerabilities v ON v.cveID=a.cveID
             WHERE LOWER(a.sourcePackage) IN ({$placeholders})
             ORDER BY a.sourcePackage,a.advisoryID"
        );
        $stmt->execute($chunk);
        while ($row = $stmt->fetch()) {
            $result[strtolower((string)$row['sourcePackage'])][] = $row;
        }
    }
    return $result;
}

function packageCoverageMetricsV2(PDO $db, ?int $assetID = null): array
{
    $filter = $assetID === null ? '' : ' AND p.assetID=:asset';
    $stmt = $db->prepare(
        "SELECT
            COUNT(*) AS packages_discovered,
            SUM(CASE WHEN p.sourcePackage IS NOT NULL AND p.sourcePackage<>'' AND p.sourceVersion IS NOT NULL AND p.sourceVersion<>'' THEN 1 ELSE 0 END) AS packages_with_source_identity,
            SUM(CASE WHEN pe.packageInventoryID IS NOT NULL THEN 1 ELSE 0 END) AS packages_evaluated,
            SUM(CASE WHEN COALESCE(pe.candidateCoverage,0)=1 THEN 1 ELSE 0 END) AS packages_with_candidate_advisories,
            SUM(CASE WHEN COALESCE(pe.authoritativeCoverage,0)=1 THEN 1 ELSE 0 END) AS packages_with_authoritative_advisory_coverage,
            SUM(CASE WHEN pe.outcome='Confirmed' THEN 1 ELSE 0 END) AS confirmed_vulnerable,
            SUM(CASE WHEN pe.outcome='Not_Affected' THEN 1 ELSE 0 END) AS not_affected_fixed,
            SUM(CASE WHEN pe.decisionReason='no_authoritative_distribution_mapping' THEN 1 ELSE 0 END) AS unknown_due_to_provider_mapping,
            SUM(CASE WHEN pe.outcome='Unknown' AND COALESCE(pe.authoritativeCoverage,0)=1 THEN 1 ELSE 0 END) AS unknown_authoritative,
            SUM(CASE WHEN pe.decisionReason='no_advisory_candidates' OR pe.packageInventoryID IS NULL THEN 1 ELSE 0 END) AS no_advisory_candidates
         FROM asset_package_inventory p
         LEFT JOIN package_evaluation_state pe ON pe.packageInventoryID=p.packageInventoryID
         WHERE p.isActive=1{$filter}"
    );
    $stmt->execute($assetID === null ? [] : [':asset'=>$assetID]);
    $row = $stmt->fetch() ?: [];
    foreach ($row as $key=>$value) $row[$key] = (int)$value;
    return $row;
}

function evaluatePackageAdvisoriesScalable(PDO $db, ?int $assetID = null): array
{
    $packages = loadActivePackagesForEvaluation($db, $assetID);
    $advisoriesBySource = loadAdvisoriesForSourcePackages($db, array_column($packages, 'sourcePackage'));

    $db->exec('CREATE TEMPORARY TABLE IF NOT EXISTS ctvlms_seen_package_exposures_v2 (exposureID BIGINT PRIMARY KEY)');
    $db->exec('DELETE FROM ctvlms_seen_package_exposures_v2');

    $upsert = $db->prepare(
        "INSERT INTO exposure_matches
            (matchKey,assetID,vulnID,softwareID,serviceID,matchType,confidence,status,evidence)
         VALUES (:key,:asset,:vuln,:software,NULL,'Package_Advisory',:confidence,:status,:evidence)
         ON DUPLICATE KEY UPDATE confidence=VALUES(confidence),evidence=VALUES(evidence),lastEvaluated=CURRENT_TIMESTAMP,
            exposureID=LAST_INSERT_ID(exposureID),
            status=CASE
                WHEN exposure_matches.status='Verified_Closed' AND VALUES(status)<>'Not_Affected' THEN 'Verification_Failed'
                WHEN exposure_matches.status IN ('Remediation_Queued','Remediating') AND VALUES(status)<>'Not_Affected' THEN exposure_matches.status
                ELSE VALUES(status)
            END"
    );
    $map = $db->prepare(
        "INSERT IGNORE INTO asset_vulnerabilities (assetID,vulnID,status,discoveredDate,notes)
         VALUES (:asset,:vuln,'Discovered',CURDATE(),'Confirmed by authoritative distribution package advisory correlation.')"
    );
    $linkAdvisory = $db->prepare(
        'INSERT INTO package_exposure_advisories (exposureID,advisoryID) VALUES (:exposure,:advisory)
         ON DUPLICATE KEY UPDATE advisoryID=VALUES(advisoryID)'
    );
    $markSeen = $db->prepare('INSERT IGNORE INTO ctvlms_seen_package_exposures_v2 (exposureID) VALUES (:exposure)');
    $evaluation = $db->prepare(
        "INSERT INTO package_evaluation_state
            (packageInventoryID,outcome,advisoryCoverage,candidateCoverage,candidateCount,authoritativeCoverage,decisionReason,provider,evidence)
         VALUES (:package,:outcome,:legacy_coverage,:candidate_coverage,:candidate_count,:authoritative_coverage,:reason,:provider,:evidence)
         ON DUPLICATE KEY UPDATE outcome=VALUES(outcome),advisoryCoverage=VALUES(advisoryCoverage),
             candidateCoverage=VALUES(candidateCoverage),candidateCount=VALUES(candidateCount),
             authoritativeCoverage=VALUES(authoritativeCoverage),decisionReason=VALUES(decisionReason),
             provider=VALUES(provider),evidence=VALUES(evidence),evaluatedAt=CURRENT_TIMESTAMP"
    );

    $contexts = [];
    $confirmed = $notAffected = $unknown = $matches = 0;
    $candidateRelationships = 0;

    foreach ($packages as $package) {
        $asset = (int)$package['assetID'];
        $contexts[$asset] ??= packageDistributionContextV2($db, $asset);
        $context = $contexts[$asset];
        $source = strtolower((string)$package['sourcePackage']);
        $rules = $source !== '' ? ($advisoriesBySource[$source] ?? []) : [];

        $authoritativeRules = [];
        $candidateRules = [];
        foreach ($rules as $rule) {
            $disposition = packageCandidateDisposition($context, $rule);
            if ($disposition === 'authoritative') $authoritativeRules[] = $rule;
            elseif ($disposition === 'candidate_only') $candidateRules[] = $rule;
        }

        // Count distinct candidate CVEs, not suite rows, so coverage remains
        // meaningful without materializing hundreds of thousands of findings.
        $candidateCves = [];
        foreach ($candidateRules as $rule) $candidateCves[(string)$rule['cveID']] = true;
        $candidateCount = count($candidateCves);
        $candidateRelationships += $candidateCount;

        $outcomes = [];
        $providers = [];
        foreach ($authoritativeRules as $rule) {
            $result = authoritativePackageAdvisoryApplicability($package, $rule, $context);
            $result['evidence']['comparison_result'] = $result['comparison_result'];
            $result['evidence']['reason'] = $result['reason'];
            $key = hash('sha256', implode('|', ['package',$package['packageInventoryID'],$rule['advisoryID']]));
            $upsert->execute([
                ':key'=>$key, ':asset'=>$asset, ':vuln'=>$rule['vulnID'], ':software'=>$package['softwareID'],
                ':confidence'=>$result['confidence'], ':status'=>$result['status'],
                ':evidence'=>json_encode($result['evidence'], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            ]);
            $exposureID = (int)$db->lastInsertId();
            $linkAdvisory->execute([':exposure'=>$exposureID, ':advisory'=>$rule['advisoryID']]);
            $markSeen->execute([':exposure'=>$exposureID]);
            if ($result['status'] === 'Confirmed') {
                $confirmed++;
                $map->execute([':asset'=>$asset,':vuln'=>$rule['vulnID']]);
            } elseif ($result['status'] === 'Not_Affected') {
                $notAffected++;
            } else {
                $unknown++;
            }
            $matches++;
            $outcomes[] = $result['status'];
            $providers[(string)$rule['provider']] = true;
        }

        $aggregate = aggregateCandidateEvaluation($candidateCount, (bool)$authoritativeRules, $outcomes);
        $evaluation->execute([
            ':package'=>$package['packageInventoryID'],
            ':outcome'=>$aggregate['outcome'],
            ':legacy_coverage'=>$aggregate['authoritative_coverage'] ? 1 : 0,
            ':candidate_coverage'=>$aggregate['candidate_coverage'] ? 1 : 0,
            ':candidate_count'=>$aggregate['candidate_count'],
            ':authoritative_coverage'=>$aggregate['authoritative_coverage'] ? 1 : 0,
            ':reason'=>$aggregate['decision_reason'],
            ':provider'=>$providers ? substr(implode(',', array_keys($providers)), 0, 100) : ($candidateCount > 0 ? 'DebianSecurityTracker(candidate)' : null),
            ':evidence'=>json_encode([
                'distribution'=>$context,
                'authoritative_rules'=>count($authoritativeRules),
                'candidate_cves'=>$candidateCount,
                'decision_reason'=>$aggregate['decision_reason'],
            ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        ]);
    }

    // Cancel and demote only old authoritative package exposures which are no
    // longer present in the current authoritative evaluation. Candidate-only
    // relationships never enter this table.
    $staleFilter = $assetID === null ? '' : ' AND e.assetID=:asset';
    $params = $assetID === null ? [] : [':asset'=>$assetID];
    $cancel = $db->prepare(
        "UPDATE remediation_jobs j
         JOIN exposure_matches e ON e.exposureID=j.exposureID
         LEFT JOIN ctvlms_seen_package_exposures_v2 seen ON seen.exposureID=e.exposureID
         SET j.status='Failed',j.completedAt=CURRENT_TIMESTAMP,
             j.lastError='Authoritative package advisory applicability is no longer current.'
         WHERE e.matchType='Package_Advisory' AND seen.exposureID IS NULL
           AND j.status IN ('Queued','Awaiting_Approval','Approved'){$staleFilter}"
    );
    $cancel->execute($params);
    $staleEvidence = json_encode(['reason'=>'package_advisory_no_longer_current','evaluated_at'=>gmdate(DATE_ATOM)], JSON_UNESCAPED_SLASHES);
    $params[':evidence'] = $staleEvidence;
    $markStale = $db->prepare(
        "UPDATE exposure_matches e
         LEFT JOIN ctvlms_seen_package_exposures_v2 seen ON seen.exposureID=e.exposureID
         SET e.status='Potential',e.confidence=0.300,e.evidence=:evidence,e.lastEvaluated=CURRENT_TIMESTAMP
         WHERE e.matchType='Package_Advisory' AND seen.exposureID IS NULL
           AND e.status IN ('Confirmed','Not_Affected','Remediation_Queued'){$staleFilter}"
    );
    $markStale->execute($params);

    return [
        'packages_evaluated'=>count($packages),
        'authoritative_advisory_matches'=>$matches,
        'candidate_cve_relationships'=>$candidateRelationships,
        'confirmed'=>$confirmed,
        'not_affected'=>$notAffected,
        'unknown_authoritative'=>$unknown,
        'coverage'=>packageCoverageMetricsV2($db,$assetID),
    ];
}
