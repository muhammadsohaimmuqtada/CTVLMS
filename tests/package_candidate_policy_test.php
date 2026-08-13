<?php
require_once __DIR__ . '/../includes/package_candidate_policy.php';

$tests = 0;
function ccheck(bool $ok, string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

$kali = ['distribution'=>'kali','suite'=>'kali-rolling'];
$debian = ['distribution'=>'debian','suite'=>'sid'];
$debianRule = ['distribution'=>'debian','suite'=>'sid'];

ccheck(packageCandidateDisposition($kali, $debianRule) === 'candidate_only', 'Kali to Debian is candidate-only');
ccheck(packageCandidateDisposition($debian, $debianRule) === 'authoritative', 'matching Debian suite is authoritative');
ccheck(packageCandidateDisposition(['distribution'=>'ubuntu','suite'=>'noble'], $debianRule) === 'unmapped', 'unrelated distro is unmapped');

$candidate = aggregateCandidateEvaluation(1000, false, []);
ccheck($candidate['outcome'] === 'Unknown', 'candidate-only package remains unknown');
ccheck($candidate['candidate_coverage'] === true && $candidate['candidate_count'] === 1000, 'candidate count is summarized');
ccheck($candidate['authoritative_coverage'] === false, 'candidate-only coverage is not authoritative');
ccheck($candidate['decision_reason'] === 'no_authoritative_distribution_mapping', 'candidate reason is explicit');

$none = aggregateCandidateEvaluation(0, false, []);
ccheck($none['outcome'] === 'Unmapped' && $none['decision_reason'] === 'no_advisory_candidates', 'no candidates remains unmapped');

$confirmed = aggregateCandidateEvaluation(3, true, ['Not_Affected','Confirmed']);
ccheck($confirmed['outcome'] === 'Confirmed' && $confirmed['authoritative_coverage'] === true, 'authoritative confirmed outcome wins');

echo "PASS: {$tests} package candidate policy tests\n";
