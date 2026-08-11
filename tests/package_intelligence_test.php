<?php
require_once __DIR__ . '/../includes/package_advisories.php';
require_once __DIR__ . '/../includes/exposure.php';

$tests = 0;
function pcheck(bool $ok, string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

pcheck(debianVersionCompare('1:1.0-1', '2.0-1') > 0, 'Debian epoch wins over upstream version');
pcheck(debianVersionCompare('1.0-2', '1.0-10') < 0, 'Debian revisions compare numerically');
pcheck(debianVersionCompare('2.0~rc1-1', '2.0-1') < 0, 'tilde prerelease sorts before release');
pcheck(debianVersionCompare('1.2.3-1+kali2', '1.2.3-1+kali10') < 0, '+kali revisions use dpkg ordering');
pcheck(debianVersionCompare('1.2.3-1+kali1', '1.2.3-1') > 0, '+kali revision sorts after its Debian base');

$provider = new DebianSecurityTrackerProvider();
$records = iterator_to_array($provider->recordsFromFile(__DIR__ . '/fixtures/debian_tracker.json'), false);
pcheck(count($records) === 6, 'streamed provider parses every release record');
pcheck($records[0]['source_package'] === 'jq' && $records[0]['suite'] === 'bullseye', 'provider preserves source package mapping');
$states = array_column($records, 'state', 'cve_id');
pcheck($states['CVE-2099-1001'] === 'Fixed', 'resolved fixed-version state');
pcheck($states['CVE-2099-1003'] === 'Vulnerable', 'open vulnerable state');
pcheck($states['CVE-2099-1004'] === 'Not_Affected', 'fixed version zero means not affected');
pcheck($states['CVE-2099-1005'] === 'Unknown', 'undetermined state remains unknown');

$package = [
    'binaryPackage'=>'jq', 'binaryVersion'=>'1.7-1+kali1', 'sourcePackage'=>'jq',
    'sourceVersion'=>'1.7-1+kali1', 'identityAuthoritative'=>1,
];
$advisory = [
    'advisoryIdentifier'=>'CVE-2099-1001', 'cveID'=>'CVE-2099-1001', 'distribution'=>'debian',
    'suite'=>'sid', 'fixedVersion'=>'1.6-1', 'provider'=>'DebianSecurityTracker', 'state'=>'Fixed',
];
$kali = packageAdvisoryApplicability($package, $advisory, ['distribution'=>'kali','suite'=>'kali-rolling']);
pcheck($kali['status'] === 'Potential' && $kali['reason'] === 'kali_debian_mapping_unjustified', 'Kali divergence remains Potential');

$debian = packageAdvisoryApplicability($package, $advisory, ['distribution'=>'debian','suite'=>'sid']);
pcheck($debian['status'] === 'Not_Affected' && $debian['comparison_result'] === 'installed_gt_fixed', 'Debian fixed version uses dpkg semantics');

echo "PASS: {$tests} package intelligence tests\n";
