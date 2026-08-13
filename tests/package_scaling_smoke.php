<?php
require_once __DIR__ . '/../includes/package_candidate_policy.php';

$context = ['distribution'=>'kali','suite'=>'kali-rolling'];
$rule = ['distribution'=>'debian','suite'=>'sid'];
if (packageCandidateDisposition($context, $rule) !== 'candidate_only') {
    fwrite(STDERR, "FAIL: Kali/Debian must remain candidate-only\n");
    exit(1);
}
$result = aggregateCandidateEvaluation(687967, false, []);
if ($result['outcome'] !== 'Unknown' || $result['candidate_count'] !== 687967 || $result['authoritative_coverage']) {
    fwrite(STDERR, "FAIL: large candidate sets must remain one package-level unknown state\n");
    exit(1);
}
echo "PASS: package candidate cardinality remains bounded\n";
