<?php
require_once __DIR__ . '/../includes/lifecycle.php';
require_once __DIR__ . '/../includes/exposure.php';

$tests = 0;

function check(bool $condition, string $message): void
{
    global $tests;
    $tests++;
    if (!$condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$cpe = parseCpe23('cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*');
check($cpe !== null, 'CPE 2.3 should parse');
check($cpe['vendor'] === 'apache', 'CPE vendor should parse');
check($cpe['product'] === 'http_server', 'CPE product should parse');
check($cpe['version'] === '2.4.57', 'CPE version should parse');

$exactRule = [
    'criteria' => 'cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*',
    'vulnerable' => 1,
    'configurationComplex' => 0,
    'versionStartIncluding' => null,
    'versionStartExcluding' => null,
    'versionEndIncluding' => null,
    'versionEndExcluding' => null,
];
$match = evaluateCpeRule('cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*', $exactRule);
check($match !== null && $match['status'] === 'Confirmed', 'Exact vulnerable CPE should confirm exposure');
check(evaluateCpeRule('cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*', $exactRule) === null, 'Different exact version should not match');

$rangeRule = [
    'criteria' => 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
    'vulnerable' => 1,
    'configurationComplex' => 0,
    'versionStartIncluding' => '3.0.0',
    'versionStartExcluding' => null,
    'versionEndIncluding' => null,
    'versionEndExcluding' => '3.0.13',
];
$match = evaluateCpeRule('cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*', $rangeRule, '3.0.12');
check($match !== null && $match['status'] === 'Confirmed', 'Package version override should satisfy vulnerable range');
check(evaluateCpeRule('cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*', $rangeRule, '3.0.13') === null, 'Excluded fixed boundary should not match');

$complexRule = $rangeRule;
$complexRule['configurationComplex'] = 1;
$match = evaluateCpeRule('cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*', $complexRule, '3.0.12');
check($match !== null && $match['status'] === 'Potential', 'Compound NVD rule must not auto-confirm from one CPE');
check($match['confidence'] <= 0.700, 'Compound NVD rule confidence must be capped');

$transitions = lifecycleTransitions();
check(in_array('Triaged', $transitions['Discovered'], true), 'Discovered should transition to Triaged');
check(!in_array('Verified_Closed', $transitions['Discovered'], true), 'Discovered must not jump to Verified Closed');
check(in_array('Verified_Closed', $transitions['Remediated'], true), 'Remediated should allow verified closure');

$_SESSION = ['role' => 'Viewer'];
check(canAcceptRisk() === false, 'Viewer must not accept risk');
$_SESSION = ['role' => 'Vuln_Manager'];
check(canAcceptRisk() === true, 'Vulnerability Manager may accept risk');
check(canVerifyRemediation() === true, 'Vulnerability Manager may verify remediation');

echo "PASS: {$tests} policy tests\n";
