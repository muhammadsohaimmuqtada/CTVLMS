<?php
/** Package advisory candidate policy and coverage semantics. */

function packageCandidateDisposition(array $distribution, array $advisory): string
{
    $endpointDistribution = strtolower(trim((string)($distribution['distribution'] ?? '')));
    $endpointSuite = strtolower(trim((string)($distribution['suite'] ?? '')));
    $advisoryDistribution = strtolower(trim((string)($advisory['distribution'] ?? '')));
    $advisorySuite = strtolower(trim((string)($advisory['suite'] ?? '')));

    if ($endpointDistribution !== '' && $endpointDistribution === $advisoryDistribution &&
        $endpointSuite !== '' && $endpointSuite === $advisorySuite) {
        return 'authoritative';
    }

    if ($endpointDistribution === 'kali' && $advisoryDistribution === 'debian') {
        return 'candidate_only';
    }

    return 'unmapped';
}

function aggregateCandidateEvaluation(int $candidateCount, bool $authoritativeCoverage, array $authoritativeOutcomes = []): array
{
    if ($authoritativeCoverage) {
        $outcome = in_array('Confirmed', $authoritativeOutcomes, true) ? 'Confirmed'
            : (in_array('Potential', $authoritativeOutcomes, true) ? 'Unknown'
            : (in_array('Not_Affected', $authoritativeOutcomes, true) ? 'Not_Affected' : 'Unmapped'));
        return [
            'outcome' => $outcome,
            'candidate_coverage' => $candidateCount > 0,
            'candidate_count' => $candidateCount,
            'authoritative_coverage' => true,
            'decision_reason' => 'authoritative_distribution_provider',
        ];
    }

    if ($candidateCount > 0) {
        return [
            'outcome' => 'Unknown',
            'candidate_coverage' => true,
            'candidate_count' => $candidateCount,
            'authoritative_coverage' => false,
            'decision_reason' => 'no_authoritative_distribution_mapping',
        ];
    }

    return [
        'outcome' => 'Unmapped',
        'candidate_coverage' => false,
        'candidate_count' => 0,
        'authoritative_coverage' => false,
        'decision_reason' => 'no_advisory_candidates',
    ];
}
