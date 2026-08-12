<?php
/**
 * CTVLMS package applicability engine v2.
 *
 * Candidate advisory intelligence is intentionally kept separate from
 * materialized exposure findings. Cross-distribution source-package matches are
 * recorded at package level until a native provider or an explicit trusted
 * distribution mapping makes them authoritative for the endpoint.
 */
require_once __DIR__ . '/exposure.php';

function packageAdvisoryMappings(PDO $db, array $context): array
{
    if (($context['distribution'] ?? '') === '' || ($context['suite'] ?? '') === '') return [];
    $stmt = $db->prepare(
        "SELECT mappingID,endpointDistribution,endpointSuite,provider,advisoryDistribution,advisorySuite,
                trustState,justification,validUntil
         FROM distribution_advisory_mappings
         WHERE endpointDistribution=:distribution AND endpointSuite=:suite
           AND trustState='Authoritative'
           AND (validUntil IS NULL OR validUntil>=CURRENT_TIMESTAMP)"
    );
    $stmt->execute([
        ':distribution'=>strtolower((string)$context['distribution']),
        ':suite'=>strtolower((string)$context['suite']),
    ]);
    return $stmt->fetchAll();
}

function packageAdvisoryAuthority(array $advisory, array $context, array $mappings): ?array
{
    $endpointDistribution = strtolower((string)($context['distribution'] ?? ''));
    $endpointSuite = strtolower((string)($context['suite'] ?? ''));
    $advisoryDistribution = strtolower((string)($advisory['distribution'] ?? ''));
    $advisorySuite = strtolower((string)($advisory['suite'] ?? ''));
    $provider = (string)($advisory['provider'] ?? '');

    if ($endpointDistribution !== '' && $endpointSuite !== '' &&
        $endpointDistribution === $advisoryDistribution && $endpointSuite === $advisorySuite) {
        return ['mode'=>'native','mapping_id'=>null,'justification'=>'native_distribution_suite_match'];
    }

    foreach ($mappings as $mapping) {
        if ((string)$mapping['provider'] !== $provider) continue;
        if (strtolower((string)$mapping['advisoryDistribution']) !== $advisoryDistribution) continue;
        if (strtolower((string)$mapping['advisorySuite']) !== $advisorySuite) continue;
        return [
            'mode'=>'explicit_mapping',
            'mapping_id'=>(int)$mapping['mappingID'],
            'justification'=>(string)$mapping['justification'],
        ];
    }
    return null;
}

function packageAdvisoryApplicabilityAuthoritativeV2(
    array $package,
    array $advisory,
    array $endpointContext,
    array $authority
): array {
    $evidence = [
        'binary_package'=>$package['binaryPackage'],
        'source_package'=>$package['sourcePackage'],
        'installed_version'=>$package['binaryVersion'],
        'source_version'=>$package['sourceVersion'],
        'advisory'=>$advisory['advisoryIdentifier'],
        'cve'=>$advisory['cveID'],
        'distribution'=>$endpointContext['distribution'],
        'suite'=>$endpointContext['suite'],
        'advisory_distribution'=>$advisory['distribution'],
        'advisory_suite'=>$advisory['suite'],
        'fixed_version'=>$advisory['fixedVersion'],
        'provider'=>$advisory['provider'],
        'authority_mode'=>$authority['mode'],
        'mapping_id'=>$authority['mapping_id'],
        'mapping_justification'=>$authority['justification'],
    ];

    if (!(bool)$package['identityAuthoritative'] || empty($package['sourcePackage'])) {
        return [
            'status'=>'Potential', 'confidence'=>0.450, 'comparison_result'=>'not_compared',
            'reason'=>'package_identity_not_authoritative', 'evidence'=>$evidence,
        ];
    }

    return match ((string)$advisory['state']) {
        'Not_Affected' => [
            'status'=>'Not_Affected', 'confidence'=>0.995, 'comparison_result'=>'not_affected',
            'reason'=>'provider_marks_suite_not_affected', 'evidence'=>$evidence,
        ],
        'Vulnerable' => [
            'status'=>'Confirmed', 'confidence'=>0.995, 'comparison_result'=>'provider_vulnerable',
            'reason'=>'provider_marks_suite_vulnerable', 'evidence'=>$evidence,
        ],
        'Fixed' => packageFixedVersionApplicability($package, $advisory, $evidence),
        default => [
            'status'=>'Potential', 'confidence'=>0.500, 'comparison_result'=>'unknown',
            'reason'=>'provider_state_unknown', 'evidence'=>$evidence,
        ],
    };
}

function cleanupLegacyCandidatePackageExposures(PDO $db, ?int $assetID = null, int $batchSize = 10000): int
{
    $batchSize = max(100, min(50000, $batchSize));
    $assetClause = $assetID === null ? '' : ' AND e.assetID=' . (int)$assetID;
    $removed = 0;
    do {
        $sql = "DELETE FROM exposure_matches
                WHERE exposureID IN (
                    SELECT exposureID FROM (
                        SELECT e.exposureID
                        FROM exposure_matches e
                        LEFT JOIN remediation_jobs j ON j.exposureID=e.exposureID
                        WHERE e.matchType='Package_Advisory'
                          AND e.status='Potential'
                          AND j.jobID IS NULL
                          AND JSON_VALID(e.evidence)=1
                          AND JSON_UNQUOTE(JSON_EXTRACT(e.evidence,'$.reason')) IN
                              ('kali_debian_mapping_unjustified','distribution_or_suite_not_authoritatively_mapped')
                          {$assetClause}
                        ORDER BY e.exposureID
                        LIMIT {$batchSize}
                    ) doomed
                )";
        $deleted = $db->exec($sql);
        if ($deleted === false) throw new RuntimeException('Unable to clean legacy candidate package exposures.');
        $removed += $deleted;
    } while ($deleted === $batchSize);
    return $removed;
}

function packageEvaluationAssetsV2(PDO $db, ?int $assetID): array
{
    if ($assetID !== null) return [$assetID];
    $rows = $db->query('SELECT DISTINCT assetID FROM asset_package_inventory WHERE isActive=1 ORDER BY assetID')->fetchAll();
    return array_map(static fn(array $row): int => (int)$row['assetID'], $rows);
}

function packageCandidateSummaryV2(PDO $db, int $assetID): array
{
    $stmt = $db->prepare(
        "SELECT p.packageInventoryID,
                COUNT(DISTINCT a.cveID) AS candidateCount,
                GROUP_CONCAT(DISTINCT a.provider ORDER BY a.provider SEPARATOR ',') AS candidateProviders
         FROM asset_package_inventory p
         LEFT JOIN distribution_advisories a ON a.sourcePackage=p.sourcePackage
         WHERE p.assetID=:asset AND p.isActive=1
         GROUP BY p.packageInventoryID"
    );
    $stmt->execute([':asset'=>$assetID]);
    $out = [];
    foreach ($stmt->fetchAll() as $row) {
        $out[(int)$row['packageInventoryID']] = [
            'candidate_count'=>(int)$row['candidateCount'],
            'candidate_providers'=>(string)($row['candidateProviders'] ?? ''),
        ];
    }
    return $out;
}

function authoritativeAdvisorySqlV2(array $context, array $mappings): array
{
    $clauses = [];
    $params = [];
    $distribution = strtolower((string)($context['distribution'] ?? ''));
    $suite = strtolower((string)($context['suite'] ?? ''));
    if ($distribution !== '' && $suite !== '') {
        $clauses[] = '(a.distribution=:nativeDistribution AND a.suite=:nativeSuite)';
        $params[':nativeDistribution'] = $distribution;
        $params[':nativeSuite'] = $suite;
    }
    foreach (array_values($mappings) as $index=>$mapping) {
        $clauses[] = "(a.provider=:mapProvider{$index} AND a.distribution=:mapDistribution{$index} AND a.suite=:mapSuite{$index})";
        $params[":mapProvider{$index}"] = (string)$mapping['provider'];
        $params[":mapDistribution{$index}"] = strtolower((string)$mapping['advisoryDistribution']);
        $params[":mapSuite{$index}"] = strtolower((string)$mapping['advisorySuite']);
    }
    return [$clauses ? '(' . implode(' OR ', $clauses) . ')' : '1=0', $params];
}

function evaluatePackageAdvisoriesV2(PDO $db, ?int $assetID = null): array
{
    $legacyRemoved = cleanupLegacyCandidatePackageExposures($db, $assetID);
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
            (packageInventoryID,outcome,advisoryCoverage,candidateCoverage,candidateCount,
             authoritativeCoverage,authoritativeRuleCount,provider,decisionReason,evidence)
         VALUES
            (:package,:outcome,:legacyCoverage,:candidateCoverage,:candidateCount,
             :authoritativeCoverage,:authoritativeRuleCount,:provider,:reason,:evidence)
         ON DUPLICATE KEY UPDATE
            outcome=VALUES(outcome),advisoryCoverage=VALUES(advisoryCoverage),
            candidateCoverage=VALUES(candidateCoverage),candidateCount=VALUES(candidateCount),
            authoritativeCoverage=VALUES(authoritativeCoverage),authoritativeRuleCount=VALUES(authoritativeRuleCount),
            provider=VALUES(provider),decisionReason=VALUES(decisionReason),evidence=VALUES(evidence),
            evaluatedAt=CURRENT_TIMESTAMP"
    );

    $packagesEvaluated = $materialized = $confirmed = $notAffected = $unknown = 0;
    $candidateCves = 0;

    foreach (packageEvaluationAssetsV2($db, $assetID) as $currentAssetID) {
        $context = packageDistributionContext($db, $currentAssetID);
        $mappings = packageAdvisoryMappings($db, $context);
        $candidateSummary = packageCandidateSummaryV2($db, $currentAssetID);

        $packagesStmt = $db->prepare(
            "SELECT p.*,s.softwareID
             FROM asset_package_inventory p
             JOIN asset_software s ON s.softwareID=p.softwareID AND s.isActive=1
             WHERE p.assetID=:asset AND p.isActive=1"
        );
        $packagesStmt->execute([':asset'=>$currentAssetID]);
        $packages = [];
        foreach ($packagesStmt->fetchAll() as $package) $packages[(int)$package['packageInventoryID']] = $package;
        $packagesEvaluated += count($packages);

        [$authoritySql,$authorityParams] = authoritativeAdvisorySqlV2($context, $mappings);
        $rulesStmt = $db->prepare(
            "SELECT p.packageInventoryID,p.assetID,p.binaryPackage,p.binaryVersion,p.architecture,
                    p.sourcePackage,p.sourceVersion,p.upstreamSourceVersion,p.packageManager,p.inventorySource,
                    p.identityAuthoritative,s.softwareID,
                    a.*,v.vulnID
             FROM asset_package_inventory p
             JOIN asset_software s ON s.softwareID=p.softwareID AND s.isActive=1
             JOIN distribution_advisories a ON a.sourcePackage=p.sourcePackage
             JOIN vulnerabilities v ON v.cveID=a.cveID
             WHERE p.assetID=:asset AND p.isActive=1 AND {$authoritySql}
             ORDER BY p.packageInventoryID,a.advisoryID"
        );
        $ruleParams = [':asset'=>$currentAssetID] + $authorityParams;
        $rulesStmt->execute($ruleParams);

        $outcomes = [];
        $authoritativeCounts = [];
        $authoritativeProviders = [];
        foreach ($rulesStmt as $rule) {
            $packageID = (int)$rule['packageInventoryID'];
            $package = $packages[$packageID] ?? $rule;
            $authority = packageAdvisoryAuthority($rule, $context, $mappings);
            if ($authority === null) continue;
            $result = packageAdvisoryApplicabilityAuthoritativeV2($package, $rule, $context, $authority);
            $result['evidence']['comparison_result'] = $result['comparison_result'];
            $result['evidence']['reason'] = $result['reason'];

            $key = hash('sha256', implode('|', ['package-v2',$packageID,$rule['advisoryID']]));
            $upsert->execute([
                ':key'=>$key, ':asset'=>$currentAssetID, ':vuln'=>$rule['vulnID'], ':software'=>$rule['softwareID'],
                ':confidence'=>$result['confidence'], ':status'=>$result['status'],
                ':evidence'=>json_encode($result['evidence'], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            ]);
            $exposureID = (int)$db->lastInsertId();
            $linkAdvisory->execute([':exposure'=>$exposureID, ':advisory'=>$rule['advisoryID']]);
            $markSeen->execute([':exposure'=>$exposureID]);
            if ($result['status'] === 'Confirmed') {
                $confirmed++;
                $map->execute([':asset'=>$currentAssetID,':vuln'=>$rule['vulnID']]);
            } elseif ($result['status'] === 'Not_Affected') {
                $notAffected++;
            } else {
                $unknown++;
            }
            $materialized++;
            $outcomes[$packageID][] = $result['status'];
            $authoritativeCounts[$packageID] = ($authoritativeCounts[$packageID] ?? 0) + 1;
            $authoritativeProviders[$packageID][(string)$rule['provider']] = true;
        }

        foreach ($packages as $packageID=>$package) {
            $candidate = $candidateSummary[$packageID] ?? ['candidate_count'=>0,'candidate_providers'=>''];
            $candidateCount = (int)$candidate['candidate_count'];
            $candidateCves += $candidateCount;
            $statuses = $outcomes[$packageID] ?? [];
            $authoritativeRuleCount = (int)($authoritativeCounts[$packageID] ?? 0);
            $authoritativeCoverage = $authoritativeRuleCount > 0;
            $candidateCoverage = $candidateCount > 0;

            if (in_array('Confirmed', $statuses, true)) {
                $outcome = 'Confirmed'; $reason = 'authoritative_confirmed_advisory';
            } elseif (in_array('Potential', $statuses, true)) {
                $outcome = 'Unknown'; $reason = 'authoritative_advisory_unknown';
            } elseif (in_array('Not_Affected', $statuses, true)) {
                $outcome = 'Not_Affected'; $reason = 'authoritative_advisories_not_affected';
            } elseif ($candidateCoverage) {
                $outcome = 'Unknown'; $reason = 'candidate_only_no_authoritative_mapping';
            } else {
                $outcome = 'Unmapped'; $reason = 'no_advisory_candidates';
            }

            $providers = $authoritativeProviders[$packageID] ?? [];
            $provider = $providers ? implode(',', array_keys($providers)) : (string)$candidate['candidate_providers'];
            $evidence = [
                'distribution'=>$context,
                'candidate_cve_count'=>$candidateCount,
                'candidate_providers'=>$candidate['candidate_providers'],
                'authoritative_rule_count'=>$authoritativeRuleCount,
                'authoritative_providers'=>array_keys($providers),
                'decision_reason'=>$reason,
            ];
            $evaluation->execute([
                ':package'=>$packageID,
                ':outcome'=>$outcome,
                ':legacyCoverage'=>$authoritativeCoverage ? 1 : 0,
                ':candidateCoverage'=>$candidateCoverage ? 1 : 0,
                ':candidateCount'=>$candidateCount,
                ':authoritativeCoverage'=>$authoritativeCoverage ? 1 : 0,
                ':authoritativeRuleCount'=>$authoritativeRuleCount,
                ':provider'=>$provider !== '' ? substr($provider,0,100) : null,
                ':reason'=>$reason,
                ':evidence'=>json_encode($evidence, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            ]);
        }
    }

    $staleFilter = $assetID === null ? '' : ' AND e.assetID=:asset';
    $staleParams = $assetID === null ? [] : [':asset'=>$assetID];
    $cancelStale = $db->prepare(
        "UPDATE remediation_jobs j
         JOIN exposure_matches e ON e.exposureID=j.exposureID
         LEFT JOIN ctvlms_seen_package_exposures_v2 seen ON seen.exposureID=e.exposureID
         SET j.status='Failed',j.completedAt=CURRENT_TIMESTAMP,
             j.lastError='Package advisory applicability is no longer authoritative/current.'
         WHERE e.matchType='Package_Advisory' AND seen.exposureID IS NULL
           AND j.status IN ('Queued','Awaiting_Approval','Approved'){$staleFilter}"
    );
    $cancelStale->execute($staleParams);

    $staleEvidence = json_encode([
        'reason'=>'package_advisory_no_longer_authoritative_or_current',
        'evaluated_at'=>gmdate(DATE_ATOM),
    ], JSON_UNESCAPED_SLASHES);
    $staleParams[':evidence'] = $staleEvidence;
    $markStale = $db->prepare(
        "UPDATE exposure_matches e
         LEFT JOIN ctvlms_seen_package_exposures_v2 seen ON seen.exposureID=e.exposureID
         SET e.status='Potential',e.confidence=0.300,e.evidence=:evidence,e.lastEvaluated=CURRENT_TIMESTAMP
         WHERE e.matchType='Package_Advisory' AND seen.exposureID IS NULL
           AND e.status IN ('Confirmed','Not_Affected','Remediation_Queued'){$staleFilter}"
    );
    $markStale->execute($staleParams);

    return [
        'packages_evaluated'=>$packagesEvaluated,
        'candidate_advisory_cves'=>$candidateCves,
        'materialized_advisory_findings'=>$materialized,
        'confirmed'=>$confirmed,
        'not_affected'=>$notAffected,
        'unknown_authoritative'=>$unknown,
        'legacy_candidate_exposures_removed'=>$legacyRemoved,
        'coverage'=>packageCoverageMetricsV2($db,$assetID),
    ];
}

function packageCoverageMetricsV2(PDO $db, ?int $assetID = null): array
{
    $filter = $assetID === null ? '' : ' AND p.assetID=:asset';
    $stmt = $db->prepare(
        "SELECT
            COUNT(*) AS packages_discovered,
            SUM(CASE WHEN p.sourcePackage IS NOT NULL AND p.sourcePackage<>'' AND p.sourceVersion IS NOT NULL AND p.sourceVersion<>'' THEN 1 ELSE 0 END) AS packages_with_source_identity,
            SUM(CASE WHEN pe.packageInventoryID IS NOT NULL THEN 1 ELSE 0 END) AS packages_evaluated,
            SUM(CASE WHEN pe.candidateCoverage=1 THEN 1 ELSE 0 END) AS packages_with_candidate_advisories,
            SUM(CASE WHEN pe.authoritativeCoverage=1 THEN 1 ELSE 0 END) AS packages_with_authoritative_advisory_coverage,
            SUM(CASE WHEN pe.outcome='Confirmed' THEN 1 ELSE 0 END) AS confirmed_vulnerable,
            SUM(CASE WHEN pe.outcome='Not_Affected' THEN 1 ELSE 0 END) AS not_affected_fixed,
            SUM(CASE WHEN pe.outcome='Unknown' AND pe.decisionReason='candidate_only_no_authoritative_mapping' THEN 1 ELSE 0 END) AS unknown_due_to_provider_mapping,
            SUM(CASE WHEN pe.outcome='Unknown' AND pe.authoritativeCoverage=1 THEN 1 ELSE 0 END) AS unknown_authoritative,
            SUM(CASE WHEN pe.packageInventoryID IS NOT NULL AND pe.candidateCoverage=0 THEN 1 ELSE 0 END) AS no_advisory_candidates,
            SUM(CASE WHEN pe.packageInventoryID IS NULL THEN 1 ELSE 0 END) AS not_yet_evaluated
         FROM asset_package_inventory p
         LEFT JOIN package_evaluation_state pe ON pe.packageInventoryID=p.packageInventoryID
         WHERE p.isActive=1{$filter}"
    );
    $stmt->execute($assetID === null ? [] : [':asset'=>$assetID]);
    $row = $stmt->fetch() ?: [];
    foreach ($row as $key=>$value) $row[$key] = (int)$value;
    $row['packages_with_advisory_coverage'] = $row['packages_with_authoritative_advisory_coverage'] ?? 0;
    $row['unknown_unmapped'] =
        ($row['unknown_due_to_provider_mapping'] ?? 0) +
        ($row['unknown_authoritative'] ?? 0) +
        ($row['no_advisory_candidates'] ?? 0) +
        ($row['not_yet_evaluated'] ?? 0);
    return $row;
}
