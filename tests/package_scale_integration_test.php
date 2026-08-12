<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/exposure.php';
require_once __DIR__ . '/../includes/package_engine_v2.php';

$tests = 0;
function scalecheck(bool $ok, string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}
$db = getDB();

function createPackageFixture(PDO $db, string $assetName, string $ip, string $distribution, string $suite,
                              string $packageName, string $version): array {
    $asset = $db->prepare("INSERT INTO assets (assetName,assetType,ipAddress,osPlatform,environment) VALUES (:name,'Workstation',:ip,:os,'Test')");
    $asset->execute([':name'=>$assetName,':ip'=>$ip,':os'=>$distribution]);
    $assetID = (int)$db->lastInsertId();
    $fact = $db->prepare("INSERT INTO asset_facts (assetID,factKey,factValue,source,confidence) VALUES (:asset,:key,:value,'Local',1)");
    foreach (['os_id'=>$distribution,'distribution_suite'=>$suite] as $key=>$value) {
        $fact->execute([':asset'=>$assetID,':key'=>$key,':value'=>$value]);
    }
    $software = $db->prepare("INSERT INTO asset_software (assetID,product,version,packageManager,packageName,source,isActive) VALUES (:asset,:product,:version,'apt',:package,'Agent',1)");
    $software->execute([':asset'=>$assetID,':product'=>$packageName,':version'=>$version,':package'=>$packageName]);
    $softwareID = (int)$db->lastInsertId();
    $package = $db->prepare(
        "INSERT INTO asset_package_inventory
            (softwareID,assetID,binaryPackage,binaryVersion,architecture,sourcePackage,sourceVersion,
             upstreamSourceVersion,packageManager,inventorySource,identityAuthoritative,isActive)
         VALUES (:software,:asset,:package,:version,'amd64',:source,:sourceVersion,'1.0','apt','Local_dpkg',1,1)"
    );
    $package->execute([
        ':software'=>$softwareID,':asset'=>$assetID,':package'=>$packageName,':version'=>$version,
        ':source'=>$packageName,':sourceVersion'=>$version,
    ]);
    return [$assetID,$softwareID,(int)$db->lastInsertId()];
}

[$kaliAsset,$kaliSoftware,$kaliPackage] = createPackageFixture(
    $db,'kali-scale-fixture','198.51.100.50','kali','kali-rolling','scale-pkg','1.0-1+kali1'
);

$vuln = $db->prepare(
    "INSERT INTO vulnerabilities (cveID,title,description,cvssScore,severity,publishedDate)
     VALUES (:cve,:title,'scale fixture',5.0,'Medium',CURDATE())"
);
$advisory = $db->prepare(
    "INSERT INTO distribution_advisories
        (recordKey,advisoryIdentifier,cveID,distribution,suite,sourcePackage,state,fixedVersion,
         sourceUrl,dataSourceIdentifier,provider,providerRecordJson)
     VALUES (:key,:cve,:cve,'debian','sid','scale-pkg','Fixed','2.0-1',
             'https://security-tracker.debian.org/tracker/data/json','scale-fixture','DebianSecurityTracker','{}')"
);
$db->beginTransaction();
try {
    for ($i=0; $i<1000; $i++) {
        $cve = sprintf('CVE-2097-%04d', $i + 1000);
        $vuln->execute([':cve'=>$cve,':title'=>$cve . ' scale candidate']);
        $advisory->execute([':key'=>hash('sha256','scale|' . $cve),':cve'=>$cve]);
    }
    $db->commit();
} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    throw $e;
}

$legacyVulnID = (int)$db->query("SELECT vulnID FROM vulnerabilities WHERE cveID='CVE-2097-1000'")->fetchColumn();
$db->prepare(
    "INSERT INTO exposure_matches
        (matchKey,assetID,vulnID,softwareID,matchType,confidence,status,evidence)
     VALUES (:key,:asset,:vuln,:software,'Package_Advisory',0.5,'Potential',:evidence)"
)->execute([
    ':key'=>hash('sha256','legacy-kali-candidate'),':asset'=>$kaliAsset,':vuln'=>$legacyVulnID,':software'=>$kaliSoftware,
    ':evidence'=>json_encode(['reason'=>'kali_debian_mapping_unjustified'],JSON_UNESCAPED_SLASHES),
]);

$result = evaluatePackageAdvisoriesV2($db,$kaliAsset);
scalecheck($result['packages_evaluated'] === 1, 'Kali package is evaluated once');
scalecheck($result['legacy_candidate_exposures_removed'] === 1, 'legacy cross-distro candidate exposure is removed');
scalecheck($result['materialized_advisory_findings'] === 0, '1000 cross-distro candidate CVEs create zero exposure rows');
scalecheck((int)$db->query("SELECT COUNT(*) FROM exposure_matches WHERE assetID={$kaliAsset} AND matchType='Package_Advisory'")->fetchColumn() === 0,
    'Kali candidate-only intelligence is not materialized as findings');
$state = $db->query("SELECT candidateCoverage,candidateCount,authoritativeCoverage,authoritativeRuleCount,outcome,decisionReason FROM package_evaluation_state WHERE packageInventoryID={$kaliPackage}")->fetch();
scalecheck((int)$state['candidateCoverage'] === 1 && (int)$state['candidateCount'] === 1000,
    'candidate coverage and cardinality are retained at package level');
scalecheck((int)$state['authoritativeCoverage'] === 0 && (int)$state['authoritativeRuleCount'] === 0,
    'cross-distro candidates do not become authoritative coverage');
scalecheck($state['outcome'] === 'Unknown' && $state['decisionReason'] === 'candidate_only_no_authoritative_mapping',
    'candidate-only package has explicit unknown mapping reason');
$coverage = packageCoverageMetricsV2($db,$kaliAsset);
scalecheck($coverage['packages_with_candidate_advisories'] === 1 && $coverage['packages_with_authoritative_advisory_coverage'] === 0,
    'coverage separates candidate from authoritative advisories');
scalecheck($coverage['unknown_due_to_provider_mapping'] === 1 && $coverage['confirmed_vulnerable'] === 0,
    'Kali candidate package is unknown, not falsely confirmed');
$db->prepare("INSERT INTO asset_patch_policies (assetID,mode,requireVerifiedBackup,transport) VALUES (:asset,'Approval',0,'None')")->execute([':asset'=>$kaliAsset]);
scalecheck(queueEligibleRemediationJobs($db,$kaliAsset) === 0, 'candidate-only package never queues remediation');

$repeat = evaluatePackageAdvisoriesV2($db,$kaliAsset);
scalecheck($repeat['materialized_advisory_findings'] === 0 &&
    (int)$db->query("SELECT COUNT(*) FROM exposure_matches WHERE assetID={$kaliAsset} AND matchType='Package_Advisory'")->fetchColumn() === 0,
    'repeated candidate evaluation is idempotent and row-stable');

[$debianAsset,$debianSoftware,$debianPackage] = createPackageFixture(
    $db,'debian-v2-fixture','198.51.100.51','debian','sid','native-v2-pkg','1.0-1'
);
$cve = 'CVE-2097-9999';
$vuln->execute([':cve'=>$cve,':title'=>$cve . ' native fixture']);
$db->prepare(
    "INSERT INTO distribution_advisories
        (recordKey,advisoryIdentifier,cveID,distribution,suite,sourcePackage,state,fixedVersion,
         sourceUrl,dataSourceIdentifier,provider,providerRecordJson)
     VALUES (:key,:cve,:cve,'debian','sid','native-v2-pkg','Fixed','2.0-1',
             'https://security-tracker.debian.org/tracker/data/json','native-fixture','DebianSecurityTracker','{}')"
)->execute([':key'=>hash('sha256','native|' . $cve),':cve'=>$cve]);
$native = evaluatePackageAdvisoriesV2($db,$debianAsset);
scalecheck($native['materialized_advisory_findings'] === 1 && $native['confirmed'] === 1,
    'native Debian advisory remains a materialized confirmed finding');
$nativeCoverage = packageCoverageMetricsV2($db,$debianAsset);
scalecheck($nativeCoverage['packages_with_authoritative_advisory_coverage'] === 1 && $nativeCoverage['confirmed_vulnerable'] === 1,
    'native Debian package receives authoritative coverage');

$db->prepare(
    "INSERT INTO distribution_advisory_mappings
        (endpointDistribution,endpointSuite,provider,advisoryDistribution,advisorySuite,trustState,justification)
     VALUES ('kali','kali-rolling','DebianSecurityTracker','debian','sid','Authoritative','CI-only explicit trust fixture')"
)->execute();
$mapped = packageAdvisoryMappings($db,['distribution'=>'kali','suite'=>'kali-rolling']);
scalecheck(count($mapped) === 1 && $mapped[0]['trustState'] === 'Authoritative',
    'explicit distro mapping can be represented without implicit trust');

echo "PASS: {$tests} package scale integration tests\n";
