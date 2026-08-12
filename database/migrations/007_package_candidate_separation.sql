USE ctvlms;

-- CTVLMS v3.2: separate package advisory candidates from authoritative
-- exposure findings. Cross-distribution candidates stay at package-evaluation
-- level until a native provider or an explicit trusted mapping exists.

ALTER TABLE package_evaluation_state
    ADD COLUMN IF NOT EXISTS candidateCoverage BOOLEAN NOT NULL DEFAULT FALSE AFTER advisoryCoverage,
    ADD COLUMN IF NOT EXISTS candidateCount INT NOT NULL DEFAULT 0 AFTER candidateCoverage,
    ADD COLUMN IF NOT EXISTS authoritativeCoverage BOOLEAN NOT NULL DEFAULT FALSE AFTER candidateCount,
    ADD COLUMN IF NOT EXISTS authoritativeRuleCount INT NOT NULL DEFAULT 0 AFTER authoritativeCoverage,
    ADD COLUMN IF NOT EXISTS decisionReason VARCHAR(120) NOT NULL DEFAULT 'requires_re_evaluation' AFTER provider;

ALTER TABLE package_evaluation_state
    ADD INDEX IF NOT EXISTS idx_package_eval_candidate (candidateCoverage, authoritativeCoverage, outcome),
    ADD INDEX IF NOT EXISTS idx_package_eval_reason (decisionReason, evaluatedAt);

-- Existing rows keep their historical fields, while the new v2 coverage columns
-- default to untrusted/unevaluated until the v2 engine refreshes them.

CREATE TABLE IF NOT EXISTS distribution_advisory_mappings (
    mappingID BIGINT AUTO_INCREMENT PRIMARY KEY,
    endpointDistribution VARCHAR(50) NOT NULL,
    endpointSuite VARCHAR(80) NOT NULL,
    provider VARCHAR(100) NOT NULL,
    advisoryDistribution VARCHAR(50) NOT NULL,
    advisorySuite VARCHAR(80) NOT NULL,
    trustState ENUM('Authoritative','Disabled') NOT NULL DEFAULT 'Disabled',
    justification TEXT NOT NULL,
    validUntil DATETIME,
    createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_distribution_advisory_mapping
        (endpointDistribution,endpointSuite,provider,advisoryDistribution,advisorySuite),
    INDEX idx_distribution_mapping_lookup
        (endpointDistribution,endpointSuite,trustState,validUntil)
);
