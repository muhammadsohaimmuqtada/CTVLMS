<?php
/** Deterministic helper fixture for scale semantics without materializing CVE rows. */
require_once __DIR__ . '/../includes/package_candidate_policy.php';

$rules = [];
for ($i = 0; $i < 1000; $i++) {
    $rules[] = ['distribution'=>'debian','suite'=>'sid','cveID'=>sprintf('CVE-2099-%04d', $i + 1)];
}
$context = ['distribution'=>'kali','suite'=>'kali-rolling'];
$candidates = 0;
foreach ($rules as $rule) if (packageCandidateDisposition($context, $rule) === 'candidate_only') $candidates++;
$result = aggregateCandidateEvaluation($candidates, false, []);
if ($candidates !== 1000 || $result['candidate_count'] !== 1000 || $result['outcome'] !== 'Unknown') {
    fwrite(STDERR, "FAIL: 1000 cross-distro candidates must collapse to one package-level Unknown state\n");
    exit(1);
}
echo "PASS: 1000 cross-distro candidates collapse to one package state\n";
