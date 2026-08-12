<?php
require_once __DIR__ . '/../includes/package_engine_v2.php';
require_once __DIR__ . '/../includes/package_advisory_guard.php';

$tests = 0;
function v2check(bool $ok, string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

$native = packageAdvisoryAuthority(
    ['provider'=>'DebianSecurityTracker','distribution'=>'debian','suite'=>'sid'],
    ['distribution'=>'debian','suite'=>'sid'],
    []
);
v2check($native !== null && $native['mode'] === 'native', 'native distro/suite is authoritative');

$none = packageAdvisoryAuthority(
    ['provider'=>'DebianSecurityTracker','distribution'=>'debian','suite'=>'sid'],
    ['distribution'=>'kali','suite'=>'kali-rolling'],
    []
);
v2check($none === null, 'cross-distro candidate is not authoritative without mapping');

$mapping = [[
    'mappingID'=>7,'provider'=>'DebianSecurityTracker','advisoryDistribution'=>'debian','advisorySuite'=>'sid',
    'justification'=>'validated test mapping',
]];
$mapped = packageAdvisoryAuthority(
    ['provider'=>'DebianSecurityTracker','distribution'=>'debian','suite'=>'sid'],
    ['distribution'=>'kali','suite'=>'kali-rolling'],
    $mapping
);
v2check($mapped !== null && $mapped['mode'] === 'explicit_mapping' && $mapped['mapping_id'] === 7,
    'explicit trusted mapping is authoritative');

$guard = advisorySnapshotGuardDecision(285000, 285685, 1000, 0.50, false);
v2check($guard['allowed'] === true, 'normal provider refresh passes snapshot guard');
$guard = advisorySnapshotGuardDecision(1000, 285685, 1000, 0.50, false);
v2check($guard['allowed'] === false && $guard['reason'] === 'unexpected_snapshot_shrink',
    'large provider shrink is rejected');
$guard = advisorySnapshotGuardDecision(50, null, 1000, 0.50, false);
v2check($guard['allowed'] === false && $guard['reason'] === 'below_absolute_minimum',
    'tiny first snapshot is rejected');
$guard = advisorySnapshotGuardDecision(50, 285685, 1000, 0.50, true);
v2check($guard['allowed'] === true && $guard['reason'] === 'operator_override',
    'explicit operator override permits intentional shrink');

$package = [
    'binaryPackage'=>'jq', 'binaryVersion'=>'1.7-1', 'sourcePackage'=>'jq', 'sourceVersion'=>'1.7-1',
    'identityAuthoritative'=>1,
];
$advisory = [
    'advisoryIdentifier'=>'CVE-2099-2000', 'cveID'=>'CVE-2099-2000', 'distribution'=>'debian',
    'suite'=>'sid', 'fixedVersion'=>'1.6-1', 'provider'=>'DebianSecurityTracker', 'state'=>'Fixed',
];
$result = packageAdvisoryApplicabilityAuthoritativeV2(
    $package,$advisory,['distribution'=>'debian','suite'=>'sid'],$native
);
v2check($result['status'] === 'Not_Affected' && $result['comparison_result'] === 'installed_gt_fixed',
    'authoritative fixed-version rule uses dpkg ordering');

$package['identityAuthoritative'] = 0;
$result = packageAdvisoryApplicabilityAuthoritativeV2(
    $package,$advisory,['distribution'=>'debian','suite'=>'sid'],$native
);
v2check($result['status'] === 'Potential' && $result['reason'] === 'package_identity_not_authoritative',
    'non-authoritative package identity cannot become definitive');

echo "PASS: {$tests} package engine v2 tests\n";
