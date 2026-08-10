<?php
require_once __DIR__ . '/../includes/lifecycle.php';
require_once __DIR__ . '/../includes/exposure.php';

$tests = 0;
function check(bool $condition, string $message): void {
    global $tests; $tests++;
    if (!$condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

$cpe = parseCpe23('cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*');
check($cpe !== null, 'CPE 2.3 should parse');
check($cpe['vendor'] === 'apache', 'CPE vendor should parse');
check($cpe['product'] === 'http_server', 'CPE product should parse');
check($cpe['version'] === '2.4.57', 'CPE version should parse');

$nmapCpe = parseCpe23('cpe:/a:apache:http_server:2.4.68');
check($nmapCpe !== null, 'Nmap CPE URI binding should parse');
check($nmapCpe['part'] === 'a', 'Nmap CPE part should parse');
check($nmapCpe['vendor'] === 'apache', 'Nmap CPE vendor should parse');
check($nmapCpe['product'] === 'http_server', 'Nmap CPE product should parse');
check($nmapCpe['version'] === '2.4.68', 'Nmap CPE version should parse');

$exactRule = [
    'criteria' => 'cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*',
    'vulnerable' => 1, 'configurationComplex' => 0,
    'versionStartIncluding' => null, 'versionStartExcluding' => null,
    'versionEndIncluding' => null, 'versionEndExcluding' => null,
];
$match = evaluateCpeRule('cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*', $exactRule);
check($match !== null && $match['status'] === 'Confirmed', 'Exact vulnerable CPE should confirm exposure');
check(evaluateCpeRule('cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*', $exactRule) === null, 'Different exact version should not match');

$nvdExactForNmap = $exactRule;
$nvdExactForNmap['criteria'] = 'cpe:2.3:a:apache:http_server:2.4.68:*:*:*:*:*:*:*';
$nmapMatch = evaluateCpeRule('cpe:/a:apache:http_server:2.4.68', $nvdExactForNmap);
check($nmapMatch !== null && $nmapMatch['status'] === 'Confirmed', 'Nmap CPE URI should correlate against NVD CPE 2.3 criteria');

$rangeRule = [
    'criteria' => 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
    'vulnerable' => 1, 'configurationComplex' => 0,
    'versionStartIncluding' => '3.0.0', 'versionStartExcluding' => null,
    'versionEndIncluding' => null, 'versionEndExcluding' => '3.0.13',
];
$match = evaluateCpeRule('cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*', $rangeRule, '3.0.12');
check($match !== null && $match['status'] === 'Confirmed', 'Package version override should satisfy vulnerable range');
check(evaluateCpeRule('cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*', $rangeRule, '3.0.13') === null, 'Excluded fixed boundary should not match');

$complexRule = $rangeRule; $complexRule['configurationComplex'] = 1;
$match = evaluateCpeRule('cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*', $complexRule, '3.0.12');
check($match !== null && $match['status'] === 'Potential', 'Legacy compound NVD rule must remain Potential without raw tree');
check($match['confidence'] <= 0.700, 'Legacy compound NVD rule confidence must be capped');

$pythonWindowsConfig = [[
    'operator' => 'AND',
    'nodes' => [
        ['operator'=>'OR','cpeMatch'=>[['vulnerable'=>true,'criteria'=>'cpe:2.3:a:python:python:*:*:*:*:*:*:*:*','versionEndIncluding'=>'3.14.4']]],
        ['operator'=>'OR','cpeMatch'=>[['vulnerable'=>false,'criteria'=>'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*']]],
    ],
]];
$pythonInventory = [['cpe'=>'cpe:/a:python:python:3.13.14','version_override'=>null]];
$linuxContext = ['inventory'=>$pythonInventory,'platform_cpes'=>[['cpe'=>'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*']]];
$windowsContext = ['inventory'=>$pythonInventory,'platform_cpes'=>[['cpe'=>'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*']]];
$unknownContext = ['inventory'=>$pythonInventory,'platform_cpes'=>[]];
check(evaluateNvdConfigurations($pythonWindowsConfig, $linuxContext)['state'] === APPLICABILITY_FALSE, 'Linux must fail a Windows environmental prerequisite');
check(evaluateNvdConfigurations($pythonWindowsConfig, $windowsContext)['state'] === APPLICABILITY_TRUE, 'Windows plus vulnerable Python must satisfy compound configuration');
check(evaluateNvdConfigurations($pythonWindowsConfig, $unknownContext)['state'] === APPLICABILITY_UNKNOWN, 'Missing authoritative OS evidence must remain unknown');
check(triNot(APPLICABILITY_TRUE) === APPLICABILITY_FALSE, 'Tri-state NOT true');
check(triNot(APPLICABILITY_UNKNOWN) === APPLICABILITY_UNKNOWN, 'Tri-state NOT unknown');
check(triCombine('AND', [APPLICABILITY_TRUE, APPLICABILITY_UNKNOWN]) === APPLICABILITY_UNKNOWN, 'AND true+unknown is unknown');
check(triCombine('OR', [APPLICABILITY_FALSE, APPLICABILITY_UNKNOWN]) === APPLICABILITY_UNKNOWN, 'OR false+unknown is unknown');

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
