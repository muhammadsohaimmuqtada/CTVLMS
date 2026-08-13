USE ctvlms;

-- CTVLMS v3.2: separate cross-distribution advisory candidates from
-- authoritative package applicability. Candidate intelligence is summarized
-- per package instead of being materialized as exposure rows.

ALTER TABLE package_evaluation_state
    ADD COLUMN IF NOT EXISTS candidateCoverage BOOLEAN NOT NULL DEFAULT FALSE AFTER advisoryCoverage,
    ADD COLUMN IF NOT EXISTS candidateCount INT NOT NULL DEFAULT 0 AFTER candidateCoverage,
    ADD COLUMN IF NOT EXISTS authoritativeCoverage BOOLEAN NOT NULL DEFAULT FALSE AFTER candidateCount,
    ADD COLUMN IF NOT EXISTS decisionReason VARCHAR(160) NULL AFTER authoritativeCoverage,
    ADD INDEX IF NOT EXISTS idx_package_eval_candidate (candidateCoverage, authoritativeCoverage, outcome),
    ADD INDEX IF NOT EXISTS idx_package_eval_reason (decisionReason);

-- Remove only the machine-generated, non-actionable rows produced by the old
-- Kali->Debian fallback behavior. Never touch Confirmed, remediation history,
-- manual findings, or CPE findings.
DELETE pea
FROM package_exposure_advisories pea
JOIN exposure_matches e ON e.exposureID = pea.exposureID
WHERE e.matchType = 'Package_Advisory'
  AND e.status = 'Potential'
  AND JSON_UNQUOTE(JSON_EXTRACT(e.evidence, '$.reason')) = 'kali_debian_mapping_unjustified';

DELETE e
FROM exposure_matches e
WHERE e.matchType = 'Package_Advisory'
  AND e.status = 'Potential'
  AND JSON_UNQUOTE(JSON_EXTRACT(e.evidence, '$.reason')) = 'kali_debian_mapping_unjustified';
