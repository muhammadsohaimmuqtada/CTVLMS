<?php
/**
 * CTVLMS — Asset-aware exposure correlation.
 *
 * Supports CPE 2.3 formatted strings from NVD and legacy CPE URI bindings
 * emitted by tools such as Nmap. NVD configuration trees are evaluated with
 * three-valued logic (true / false / unknown) so compound platform conditions
 * are not collapsed into false-positive confirmations.
 */

require_once __DIR__ . '/debian_version.php';

const APPLICABILITY_TRUE = 'true';
const APPLICABILITY_FALSE = 'false';
const APPLICABILITY_UNKNOWN = 'unknown';

function decodeCpeComponent(string $value): string
{
    return str_replace(['\\:', '\\!', '\\?', '\\\\'], [':', '!', '?', '\\'], $value);
}

function parseCpe23(?string $cpe): ?array
{
    if (!$cpe) return null;

    if (str_starts_with($cpe, 'cpe:2.3:')) {
        $parts = preg_split('/(?<!\\\\):/', $cpe);
        if (!$parts || count($parts) < 6) return null;
        return [
            'part' => strtolower(decodeCpeComponent($parts[2])),
            'vendor' => strtolower(decodeCpeComponent($parts[3])),
            'product' => strtolower(decodeCpeComponent($parts[4])),
            'version' => decodeCpeComponent($parts[5]),
        ];
    }

    if (str_starts_with($cpe, 'cpe:/')) {
        $parts = preg_split('/(?<!\\\\):/', $cpe);
        if (!$parts || count($parts) < 4) return null;
        $part = strtolower(ltrim(decodeCpeComponent($parts[1]), '/'));
        if (!in_array($part, ['a', 'o', 'h'], true)) return null;
        return [
            'part' => $part,
            'vendor' => strtolower(decodeCpeComponent($parts[2] ?? '')),
            'product' => strtolower(decodeCpeComponent($parts[3] ?? '')),
            'version' => decodeCpeComponent($parts[4] ?? '*'),
        ];
    }
    return null;
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

function evaluateCpeRule(string $inventoryCpe, array $rule, ?string $observedVersionOverride = null): ?array
{
    $observed = parseCpe23($inventoryCpe);
    $criteria = parseCpe23($rule['criteria'] ?? null);
    if (!$observed || !$criteria || cpeBaseKey($observed) !== cpeBaseKey($criteria)) return null;
    if (empty($rule['vulnerable'])) return null;

    $observedVersion = cpeVersionKnown($observedVersionOverride) ? $observedVersionOverride : $observed['version'];
    $criteriaVersion = $criteria['version'];
    $hasRange = !empty($rule['versionStartIncluding']) || !empty($rule['versionStartExcluding']) ||
        !empty($rule['versionEndIncluding']) || !empty($rule['versionEndExcluding']);

    if (cpeVersionKnown($criteriaVersion)) {
        if (!cpeVersionKnown($observedVersion) || version_compare($observedVersion, $criteriaVersion, '!=')) return null;
        $result = ['type'=>'CPE_Exact','confidence'=>0.995,'status'=>'Confirmed'];
    } elseif ($hasRange) {
        if (!cpeVersionKnown($observedVersion)) {
            $result = ['type'=>'CPE_Potential','confidence'=>0.600,'status'=>'Potential'];
        } else {
            if (!versionWithinNvdRange($observedVersion, $rule)) return null;
            $result = ['type'=>'CPE_Range','confidence'=>0.960,'status'=>'Confirmed'];
        }
    } elseif (cpeVersionKnown($observedVersion)) {
        $result = ['type'=>'CPE_Exact','confidence'=>0.950,'status'=>'Confirmed'];
    } else {
        $result = ['type'=>'CPE_Potential','confidence'=>0.650,'status'=>'Potential'];
    }

    if (!empty($rule['configurationComplex'])) {
        $result['type'] = 'CPE_Potential';
        $result['confidence'] = min($result['confidence'], 0.700);
        $result['status'] = 'Potential';
    }
    return $result;
}

function triNot(string $state): string
{
    return match ($state) {
        APPLICABILITY_TRUE => APPLICABILITY_FALSE,
        APPLICABILITY_FALSE => APPLICABILITY_TRUE,
        default => APPLICABILITY_UNKNOWN,
    };
}

function triCombine(string $operator, array $states): string
{
    if (!$states) return APPLICABILITY_UNKNOWN;
    $operator = strtoupper($operator) === 'AND' ? 'AND' : 'OR';
    if ($operator === 'AND') {
        if (in_array(APPLICABILITY_FALSE, $states, true)) return APPLICABILITY_FALSE;
        if (!in_array(APPLICABILITY_UNKNOWN, $states, true)) return APPLICABILITY_TRUE;
        return APPLICABILITY_UNKNOWN;
    }
    if (in_array(APPLICABILITY_TRUE, $states, true)) return APPLICABILITY_TRUE;
    if (!in_array(APPLICABILITY_UNKNOWN, $states, true)) return APPLICABILITY_FALSE;
    return APPLICABILITY_UNKNOWN;
}

function evaluateCriterionAgainstContext(array $criterion, array $context): array
{
    $parsedCriteria = parseCpe23($criterion['criteria'] ?? null);
    if (!$parsedCriteria) {
        return ['state'=>APPLICABILITY_UNKNOWN,'criteria'=>$criterion['criteria'] ?? null,'reason'=>'invalid_criteria'];
    }

    $items = array_merge($context['inventory'] ?? [], $context['platform_cpes'] ?? []);
    $sameBase = [];
    foreach ($items as $item) {
        $parsed = parseCpe23($item['cpe'] ?? null);
        if ($parsed && cpeBaseKey($parsed) === cpeBaseKey($parsedCriteria)) $sameBase[] = [$item, $parsed];
    }

    if (!$sameBase) {
        if ($parsedCriteria['part'] === 'o' && !empty($context['platform_cpes'])) {
            return ['state'=>APPLICABILITY_FALSE,'criteria'=>$criterion['criteria'],'reason'=>'authoritative_platform_mismatch'];
        }
        return ['state'=>APPLICABILITY_UNKNOWN,'criteria'=>$criterion['criteria'],'reason'=>'inventory_absent'];
    }

    $states = [];
    foreach ($sameBase as [$item, $parsed]) {
        $versionOverride = $item['version_override'] ?? null;
        $observedVersion = cpeVersionKnown($versionOverride) ? $versionOverride : $parsed['version'];
        $criteriaVersion = $parsedCriteria['version'];
        $hasRange = !empty($criterion['versionStartIncluding']) || !empty($criterion['versionStartExcluding']) ||
            !empty($criterion['versionEndIncluding']) || !empty($criterion['versionEndExcluding']);
        if (cpeVersionKnown($criteriaVersion)) {
            $states[] = !cpeVersionKnown($observedVersion) ? APPLICABILITY_UNKNOWN :
                (version_compare($observedVersion, $criteriaVersion, '==') ? APPLICABILITY_TRUE : APPLICABILITY_FALSE);
        } elseif ($hasRange) {
            $states[] = !cpeVersionKnown($observedVersion) ? APPLICABILITY_UNKNOWN :
                (versionWithinNvdRange($observedVersion, $criterion) ? APPLICABILITY_TRUE : APPLICABILITY_FALSE);
        } else {
            $states[] = APPLICABILITY_TRUE;
        }
    }

    $state = in_array(APPLICABILITY_TRUE, $states, true) ? APPLICABILITY_TRUE :
        (in_array(APPLICABILITY_UNKNOWN, $states, true) ? APPLICABILITY_UNKNOWN : APPLICABILITY_FALSE);
    return ['state'=>$state,'criteria'=>$criterion['criteria'],'reason'=>'cpe_evaluated'];
}

function evaluateNvdNode(array $node, array $context): array
{
    $children = [];
    foreach (($node['cpeMatch'] ?? []) as $match) if (is_array($match)) $children[] = evaluateCriterionAgainstContext($match, $context);
    foreach (($node['nodes'] ?? []) as $child) if (is_array($child)) $children[] = evaluateNvdNode($child, $context);
    $state = triCombine((string)($node['operator'] ?? 'OR'), array_column($children, 'state'));
    if (!empty($node['negate'])) $state = triNot($state);
    return [
        'state'=>$state,
        'operator'=>strtoupper((string)($node['operator'] ?? 'OR')),
        'negate'=>!empty($node['negate']),
        'children'=>$children,
    ];
}

function evaluateNvdConfigurations(array $configurations, array $context): array
{
    $evaluated = [];
    foreach ($configurations as $configuration) if (is_array($configuration)) $evaluated[] = evaluateNvdNode($configuration, $context);
    return ['state'=>triCombine('OR', array_column($evaluated, 'state')), 'configurations'=>$evaluated];
}

function loadCpeInventory(PDO $db, ?int $assetID = null): array
{
    $assetFilter = $assetID !== null ? ' AND assetID = :assetID' : '';
    $params = $assetID !== null ? [':assetID'=>$assetID] : [];
    $software = $db->prepare(
        "SELECT softwareID AS sourceID, assetID, cpe, version, packageName, packageManager
         FROM asset_software WHERE isActive=1 AND cpe IS NOT NULL AND cpe<>''{$assetFilter}"
    );
    $software->execute($params);
    $services = $db->prepare(
        "SELECT serviceID AS sourceID, assetID, cpe, version, NULL AS packageName, NULL AS packageManager
         FROM asset_services WHERE isActive=1 AND cpe IS NOT NULL AND cpe<>''{$assetFilter}"
    );
    $services->execute($params);

    $inventory = [];
    foreach ($software->fetchAll() as $row) {
        $row['sourceType'] = 'software';
        $row['version_override'] = $row['version'];
        $inventory[] = $row;
    }
    foreach ($services->fetchAll() as $row) {
        $row['sourceType'] = 'service';
        $row['version_override'] = null;
        $inventory[] = $row;
    }
    return $inventory;
}

function loadAssetContext(PDO $db, int $assetID, array $inventory): array
{
    $platform = $db->prepare(
        "SELECT platformCpeID AS sourceID, assetID, cpe, NULL AS version_override, source
         FROM asset_platform_cpes WHERE assetID=:assetID AND isActive=1"
    );
    $platform->execute([':assetID'=>$assetID]);
    $facts = $db->prepare(
        'SELECT factKey, factValue, source, confidence FROM asset_facts
         WHERE assetID=:assetID ORDER BY confidence DESC, lastSeen DESC'
    );
    $facts->execute([':assetID'=>$assetID]);
    $factMap = [];
    foreach ($facts->fetchAll() as $row) if (!array_key_exists($row['factKey'], $factMap)) $factMap[$row['factKey']] = $row['factValue'];
    return ['inventory'=>$inventory, 'platform_cpes'=>$platform->fetchAll(), 'facts'=>$factMap];
}

function loadNvdConfigurationsForVuln(PDO $db, int $vulnID): array
{
    $stmt = $db->prepare(
        "SELECT configurationJson FROM vulnerability_configurations
         WHERE vulnID=:vulnID AND source='NVD' ORDER BY configIndex"
    );
    $stmt->execute([':vulnID'=>$vulnID]);
    $out = [];
    foreach ($stmt->fetchAll() as $row) {
        $decoded = json_decode((string)$row['configurationJson'], true);
        if (is_array($decoded)) $out[] = $decoded;
    }
    return $out;
}

function reconcileInactiveExposureSources(PDO $db, ?int $assetID = null): int
{
    $sql = "SELECT e.exposureID, e.assetID, e.vulnID, e.serviceID, e.softwareID
            FROM exposure_matches e
            LEFT JOIN asset_services svc ON svc.serviceID=e.serviceID
            LEFT JOIN asset_software sw ON sw.softwareID=e.softwareID
            WHERE e.status<>'Verified_Closed'
              AND ((e.serviceID IS NOT NULL AND COALESCE(svc.isActive,0)=0)
                OR (e.softwareID IS NOT NULL AND COALESCE(sw.isActive,0)=0))";
    $params = [];
    if ($assetID !== null) { $sql .= ' AND e.assetID=:assetID'; $params[':assetID']=$assetID; }
    $stmt = $db->prepare($sql); $stmt->execute($params); $rows = $stmt->fetchAll();
    if (!$rows) return 0;
    $update = $db->prepare(
        "UPDATE exposure_matches SET status='Not_Affected', confidence=1.000,
         evidence=:evidence, lastEvaluated=CURRENT_TIMESTAMP WHERE exposureID=:id"
    );
    foreach ($rows as $row) {
        $update->execute([
            ':id'=>$row['exposureID'],
            ':evidence'=>json_encode([
                'reason'=>'inventory_source_inactive',
                'service_id'=>$row['serviceID'] ? (int)$row['serviceID'] : null,
                'software_id'=>$row['softwareID'] ? (int)$row['softwareID'] : null,
                'evaluated_at'=>gmdate(DATE_ATOM),
            ], JSON_UNESCAPED_SLASHES),
        ]);
    }
    return count($rows);
}

function evaluateExposureInventory(PDO $db, ?int $assetID = null): array
{
    $rules = $db->query(
        'SELECT vc.*, v.cveID, v.severity FROM vulnerability_cpe_matches vc
         JOIN vulnerabilities v ON v.vulnID=vc.vulnID WHERE vc.vulnerable=1'
    )->fetchAll();
    $rulesByBase = [];
    foreach ($rules as $rule) {
        $parsed = parseCpe23($rule['criteria']);
        if ($parsed) $rulesByBase[cpeBaseKey($parsed)][] = $rule;
    }

    $inventory = loadCpeInventory($db, $assetID);
    $inventoryByAsset = [];
    foreach ($inventory as $item) $inventoryByAsset[(int)$item['assetID']][] = $item;
    $matched = $potential = $confirmed = $notAffected = 0;
    $configCache = $contextCache = [];

    $upsert = $db->prepare(
        "INSERT INTO exposure_matches
            (matchKey,assetID,vulnID,softwareID,serviceID,matchType,confidence,status,evidence)
         VALUES (:key,:asset,:vuln,:software,:service,:type,:confidence,:status,:evidence)
         ON DUPLICATE KEY UPDATE
            confidence=VALUES(confidence), matchType=VALUES(matchType), evidence=VALUES(evidence),
            lastEvaluated=CURRENT_TIMESTAMP,
            status=CASE
                WHEN exposure_matches.status='Verified_Closed' AND VALUES(status)<>'Not_Affected' THEN 'Verification_Failed'
                WHEN exposure_matches.status IN ('Remediation_Queued','Remediating') AND VALUES(status)<>'Not_Affected' THEN exposure_matches.status
                ELSE VALUES(status)
            END"
    );
    $map = $db->prepare(
        "INSERT IGNORE INTO asset_vulnerabilities
            (assetID,vulnID,status,discoveredDate,notes)
         VALUES (:asset,:vuln,'Discovered',CURDATE(),:notes)"
    );

    foreach ($inventory as $item) {
        $parsed = parseCpe23($item['cpe']);
        if (!$parsed) continue;
        foreach (($rulesByBase[cpeBaseKey($parsed)] ?? []) as $rule) {
            $versionOverride = $item['sourceType'] === 'software' ? ($item['version'] ?? null) : null;
            $scoringRule = $rule;
            $scoringRule['configurationComplex'] = 0;
            $baseResult = evaluateCpeRule($item['cpe'], $scoringRule, $versionOverride);
            if ($baseResult === null) continue;

            $vulnID = (int)$rule['vulnID'];
            $asset = (int)$item['assetID'];
            if (!array_key_exists($vulnID, $configCache)) $configCache[$vulnID] = loadNvdConfigurationsForVuln($db, $vulnID);
            if (!array_key_exists($asset, $contextCache)) $contextCache[$asset] = loadAssetContext($db, $asset, $inventoryByAsset[$asset] ?? []);

            $configEvaluation = null;
            $status = $baseResult['status'];
            $type = $baseResult['type'];
            $confidence = $baseResult['confidence'];
            if ($configCache[$vulnID]) {
                $configEvaluation = evaluateNvdConfigurations($configCache[$vulnID], $contextCache[$asset]);
                if ($configEvaluation['state'] === APPLICABILITY_TRUE) {
                    $status = 'Confirmed';
                } elseif ($configEvaluation['state'] === APPLICABILITY_FALSE) {
                    $status = 'Not_Affected';
                    $confidence = 0.990;
                } else {
                    $status = 'Potential';
                    $type = 'CPE_Potential';
                    $confidence = min($confidence, 0.700);
                }
            } elseif (!empty($rule['configurationComplex'])) {
                $status = 'Potential';
                $type = 'CPE_Potential';
                $confidence = min($confidence, 0.700);
            }

            $key = hash('sha256', implode('|', [$asset,$vulnID,$item['sourceType'],$item['sourceID']]));
            $observed = parseCpe23($item['cpe']);
            $evidence = json_encode([
                'observed_cpe'=>$item['cpe'],
                'observed_version'=>$item['sourceType']==='software' ? ($item['version'] ?? null) : ($observed['version'] ?? null),
                'nvd_criteria'=>$rule['criteria'],
                'version_start_including'=>$rule['versionStartIncluding'],
                'version_start_excluding'=>$rule['versionStartExcluding'],
                'version_end_including'=>$rule['versionEndIncluding'],
                'version_end_excluding'=>$rule['versionEndExcluding'],
                'source_type'=>$item['sourceType'],
                'source_id'=>(int)$item['sourceID'],
                'cve'=>$rule['cveID'],
                'configuration_evaluation'=>$configEvaluation,
            ], JSON_UNESCAPED_SLASHES);

            $upsert->execute([
                ':key'=>$key, ':asset'=>$asset, ':vuln'=>$vulnID,
                ':software'=>$item['sourceType']==='software' ? (int)$item['sourceID'] : null,
                ':service'=>$item['sourceType']==='service' ? (int)$item['sourceID'] : null,
                ':type'=>$type, ':confidence'=>$confidence, ':status'=>$status, ':evidence'=>$evidence,
            ]);
            if ($status !== 'Not_Affected') {
                $map->execute([':asset'=>$asset, ':vuln'=>$vulnID, ':notes'=>'Automatically discovered by CTVLMS exposure correlation.']);
            }
            $matched++;
            if ($status === 'Confirmed') $confirmed++;
            elseif ($status === 'Not_Affected') $notAffected++;
            else $potential++;
        }
    }

    $inactive = reconcileInactiveExposureSources($db, $assetID);
    return [
        'inventory_items'=>count($inventory),
        'matches'=>$matched,
        'confirmed'=>$confirmed,
        'potential'=>$potential,
        'not_affected'=>$notAffected,
        'inactive_sources_reconciled'=>$inactive,
    ];
}

function packageDistributionContext(PDO $db, int $assetID): array
{
    $stmt = $db->prepare(
        "SELECT factKey,factValue FROM asset_facts
         WHERE assetID=:asset AND factKey IN ('os_id','distribution_suite')
         ORDER BY confidence DESC,lastSeen DESC"
    );
    $stmt->execute([':asset'=>$assetID]);
    $facts = [];
    foreach ($stmt->fetchAll() as $row) if (!isset($facts[$row['factKey']])) $facts[$row['factKey']] = strtolower(trim((string)$row['factValue']));
    return ['distribution'=>$facts['os_id'] ?? '', 'suite'=>$facts['distribution_suite'] ?? ''];
}

function packageAdvisoryApplicability(array $package, array $advisory, array $distribution): array
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
    if ($distribution['distribution'] === 'kali' && $advisory['distribution'] === 'debian') {
        return ['status'=>'Potential','confidence'=>0.500,'comparison_result'=>'not_compared',
            'reason'=>'kali_debian_mapping_unjustified','evidence'=>$baseEvidence];
    }
    if ($distribution['distribution'] !== $advisory['distribution'] || $distribution['suite'] === '' ||
        $distribution['suite'] !== strtolower((string)$advisory['suite'])) {
        return ['status'=>'Potential','confidence'=>0.400,'comparison_result'=>'not_compared',
            'reason'=>'distribution_or_suite_not_authoritatively_mapped','evidence'=>$baseEvidence];
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
        'Fixed' => packageFixedVersionApplicability($package, $advisory, $baseEvidence),
        default => ['status'=>'Potential','confidence'=>0.500,'comparison_result'=>'unknown',
            'reason'=>'provider_state_unknown','evidence'=>$baseEvidence],
    };
}

function packageFixedVersionApplicability(array $package, array $advisory, array $evidence): array
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

function evaluatePackageAdvisories(PDO $db, ?int $assetID = null): array
{
    $filter = $assetID === null ? '' : ' AND p.assetID=:asset';
    $packagesStmt = $db->prepare(
        "SELECT p.*,s.softwareID FROM asset_package_inventory p
         JOIN asset_software s ON s.softwareID=p.softwareID AND s.isActive=1
         WHERE p.isActive=1{$filter}"
    );
    $packagesStmt->execute($assetID === null ? [] : [':asset'=>$assetID]);
    $packages = $packagesStmt->fetchAll();
    $advisories = $db->query(
        'SELECT a.*,v.vulnID FROM distribution_advisories a JOIN vulnerabilities v ON v.cveID=a.cveID ORDER BY a.advisoryID'
    )->fetchAll();
    $bySource = [];
    foreach ($advisories as $advisory) $bySource[strtolower((string)$advisory['sourcePackage'])][] = $advisory;
    $db->exec('CREATE TEMPORARY TABLE IF NOT EXISTS ctvlms_seen_package_exposures (exposureID BIGINT PRIMARY KEY)');
    $db->exec('DELETE FROM ctvlms_seen_package_exposures');

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
    $markSeen = $db->prepare('INSERT IGNORE INTO ctvlms_seen_package_exposures (exposureID) VALUES (:exposure)');
    $evaluation = $db->prepare(
        "INSERT INTO package_evaluation_state (packageInventoryID,outcome,advisoryCoverage,provider,evidence)
         VALUES (:package,:outcome,:coverage,:provider,:evidence)
         ON DUPLICATE KEY UPDATE outcome=VALUES(outcome),advisoryCoverage=VALUES(advisoryCoverage),
             provider=VALUES(provider),evidence=VALUES(evidence),evaluatedAt=CURRENT_TIMESTAMP"
    );
    $contexts = []; $confirmed = $notAffected = $unknown = $matches = 0;
    foreach ($packages as $package) {
        $asset = (int)$package['assetID'];
        $contexts[$asset] ??= packageDistributionContext($db, $asset);
        $rules = $bySource[strtolower((string)$package['sourcePackage'])] ?? [];
        $nativeRules = array_values(array_filter($rules, fn(array $r): bool =>
            strtolower((string)$r['distribution']) === $contexts[$asset]['distribution'] &&
            strtolower((string)$r['suite']) === $contexts[$asset]['suite']));
        if ($nativeRules) {
            $rules = $nativeRules;
        } elseif ($contexts[$asset]['distribution'] === 'kali') {
            $byCve = [];
            foreach ($rules as $rule) {
                if (strtolower((string)$rule['distribution']) !== 'debian') continue;
                $cve = $rule['cveID'];
                if (!isset($byCve[$cve]) || strtolower((string)$rule['suite']) === 'sid') $byCve[$cve] = $rule;
            }
            $rules = array_values($byCve);
        } else $rules = [];
        $packageOutcomes = [];
        foreach ($rules as $rule) {
            $result = packageAdvisoryApplicability($package, $rule, $contexts[$asset]);
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
            if ($result['status'] === 'Confirmed') { $confirmed++; $map->execute([':asset'=>$asset,':vuln'=>$rule['vulnID']]); }
            elseif ($result['status'] === 'Not_Affected') $notAffected++;
            else $unknown++;
            $matches++; $packageOutcomes[] = $result['status'];
        }
        $outcome = in_array('Confirmed', $packageOutcomes, true) ? 'Confirmed'
            : (in_array('Potential', $packageOutcomes, true) ? 'Unknown'
            : (in_array('Not_Affected', $packageOutcomes, true) ? 'Not_Affected' : 'Unmapped'));
        $evaluation->execute([
            ':package'=>$package['packageInventoryID'], ':outcome'=>$outcome, ':coverage'=>$rules ? 1 : 0,
            ':provider'=>$rules ? substr(implode(',', array_unique(array_column($rules, 'provider'))), 0, 100) : null,
            ':evidence'=>json_encode(['distribution'=>$contexts[$asset], 'advisory_rules'=>count($rules)], JSON_UNESCAPED_SLASHES),
        ]);
    }
    $staleFilter = $assetID === null ? '' : ' AND e.assetID=:asset';
    $staleParams = $assetID === null ? [] : [':asset'=>$assetID];
    $cancelStale = $db->prepare(
        "UPDATE remediation_jobs j
         JOIN exposure_matches e ON e.exposureID=j.exposureID
         LEFT JOIN ctvlms_seen_package_exposures seen ON seen.exposureID=e.exposureID
         SET j.status='Failed',j.completedAt=CURRENT_TIMESTAMP,
             j.lastError='Package advisory applicability is no longer current.'
         WHERE e.matchType='Package_Advisory' AND seen.exposureID IS NULL
           AND j.status IN ('Queued','Awaiting_Approval','Approved'){$staleFilter}"
    );
    $cancelStale->execute($staleParams);
    $staleEvidence = json_encode(['reason'=>'package_advisory_no_longer_current','evaluated_at'=>gmdate(DATE_ATOM)], JSON_UNESCAPED_SLASHES);
    $staleParams[':evidence'] = $staleEvidence;
    $markStale = $db->prepare(
        "UPDATE exposure_matches e
         LEFT JOIN ctvlms_seen_package_exposures seen ON seen.exposureID=e.exposureID
         SET e.status='Potential',e.confidence=0.300,e.evidence=:evidence,e.lastEvaluated=CURRENT_TIMESTAMP
         WHERE e.matchType='Package_Advisory' AND seen.exposureID IS NULL
           AND e.status IN ('Confirmed','Not_Affected','Remediation_Queued'){$staleFilter}"
    );
    $markStale->execute($staleParams);
    return ['packages_evaluated'=>count($packages),'advisory_matches'=>$matches,'confirmed'=>$confirmed,
        'not_affected'=>$notAffected,'unknown'=>$unknown,'coverage'=>packageCoverageMetrics($db,$assetID)];
}

function packageCoverageMetrics(PDO $db, ?int $assetID = null): array
{
    $filter = $assetID === null ? '' : ' AND p.assetID=:asset';
    $stmt = $db->prepare(
        "SELECT
            COUNT(*) AS packages_discovered,
            SUM(CASE WHEN p.sourcePackage IS NOT NULL AND p.sourcePackage<>'' AND p.sourceVersion IS NOT NULL AND p.sourceVersion<>'' THEN 1 ELSE 0 END) AS packages_with_source_identity,
            SUM(CASE WHEN pe.packageInventoryID IS NOT NULL THEN 1 ELSE 0 END) AS packages_evaluated,
            SUM(CASE WHEN pe.advisoryCoverage=1 THEN 1 ELSE 0 END) AS packages_with_advisory_coverage,
            SUM(CASE WHEN pe.outcome='Confirmed' THEN 1 ELSE 0 END) AS confirmed_vulnerable,
            SUM(CASE WHEN pe.outcome='Not_Affected' THEN 1 ELSE 0 END) AS not_affected_fixed,
            SUM(CASE WHEN pe.outcome IN ('Unknown','Unmapped') OR pe.packageInventoryID IS NULL THEN 1 ELSE 0 END) AS unknown_unmapped
         FROM asset_package_inventory p
         LEFT JOIN package_evaluation_state pe ON pe.packageInventoryID=p.packageInventoryID
         WHERE p.isActive=1{$filter}"
    );
    $stmt->execute($assetID === null ? [] : [':asset'=>$assetID]);
    $row = $stmt->fetch() ?: [];
    foreach ($row as $key=>$value) $row[$key] = (int)$value;
    return $row;
}

function assetHasValidBackupEvidence(PDO $db, int $assetID): bool
{
    $stmt = $db->prepare('SELECT 1 FROM asset_backup_evidence WHERE assetID=:asset AND (validUntil IS NULL OR validUntil>=CURRENT_TIMESTAMP) LIMIT 1');
    $stmt->execute([':asset'=>$assetID]);
    return (bool)$stmt->fetchColumn();
}

function packageIdentityNameIsValid(string $package): bool
{
    return $package !== '' && strlen($package) <= 200 &&
        preg_match('/^[A-Za-z0-9][A-Za-z0-9.+:_-]*$/', $package) === 1;
}

function queueEligibleRemediationJobs(PDO $db, ?int $assetID = null): int
{
    $sql = "SELECT e.exposureID,e.assetID,e.softwareID,s.packageManager,s.packageName,s.version,
                   p.mode,p.requireVerifiedBackup
            FROM exposure_matches e
            JOIN asset_software s ON s.softwareID=e.softwareID AND s.isActive=1
            LEFT JOIN asset_package_inventory pi ON pi.softwareID=s.softwareID AND pi.isActive=1
            LEFT JOIN package_exposure_advisories pea ON pea.exposureID=e.exposureID
            LEFT JOIN distribution_advisories da ON da.advisoryID=pea.advisoryID
            JOIN asset_patch_policies p ON p.assetID=e.assetID
            WHERE e.status='Confirmed' AND s.packageName IS NOT NULL AND s.packageName<>''
              AND s.packageManager IN ('apt','dnf','yum','apk') AND p.mode<>'Disabled'
              AND (e.matchType<>'Package_Advisory' OR
                   (pi.identityAuthoritative=1 AND pi.binaryPackage=s.packageName AND pi.packageManager=s.packageManager
                    AND da.advisoryID IS NOT NULL))";
    $params = [];
    if ($assetID !== null) { $sql .= ' AND e.assetID=:assetID'; $params[':assetID']=$assetID; }
    $stmt = $db->prepare($sql); $stmt->execute($params); $rows = $stmt->fetchAll();
    $exists = $db->prepare("SELECT 1 FROM remediation_jobs WHERE exposureID=:exposure AND status IN ('Queued','Awaiting_Approval','Approved','Running') LIMIT 1");
    $insert = $db->prepare('INSERT INTO remediation_jobs (exposureID,assetID,softwareID,packageManager,packageName,fromVersion,status) VALUES (:exposure,:asset,:software,:manager,:package,:version,:status)');
    $mark = $db->prepare("UPDATE exposure_matches SET status='Remediation_Queued' WHERE exposureID=:id");
    $queued = 0;
    foreach ($rows as $row) {
        if (!packageIdentityNameIsValid((string)$row['packageName'])) continue;
        $exists->execute([':exposure'=>$row['exposureID']]);
        if ($exists->fetchColumn()) continue;
        if ($row['mode']==='Auto' && (bool)$row['requireVerifiedBackup'] && !assetHasValidBackupEvidence($db, (int)$row['assetID'])) continue;
        $status = $row['mode']==='Auto' ? 'Queued' : 'Awaiting_Approval';
        $insert->execute([':exposure'=>$row['exposureID'],':asset'=>$row['assetID'],':software'=>$row['softwareID'],':manager'=>$row['packageManager'],':package'=>$row['packageName'],':version'=>$row['version'],':status'=>$status]);
        $mark->execute([':id'=>$row['exposureID']]);
        $queued++;
    }
    return $queued;
}
