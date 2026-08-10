USE ctvlms;

-- CTVLMS v3: authoritative endpoint facts, inventory freshness, and preservation
-- of complete NVD applicability statements.

ALTER TABLE asset_services
    ADD COLUMN isActive BOOLEAN NOT NULL DEFAULT TRUE AFTER cpe,
    ADD COLUMN lastSeenScanRunID BIGINT NULL AFTER lastSeen,
    ADD CONSTRAINT fk_asset_services_scan_run
        FOREIGN KEY (lastSeenScanRunID) REFERENCES scan_runs(scanRunID) ON DELETE SET NULL,
    ADD INDEX idx_service_active_cpe (isActive, cpe(191));

ALTER TABLE asset_software
    DROP INDEX uq_asset_software,
    ADD COLUMN isActive BOOLEAN NOT NULL DEFAULT TRUE AFTER source,
    ADD UNIQUE KEY uq_asset_software_source (assetID, product, version, packageName, source),
    ADD INDEX idx_software_active_cpe (isActive, cpe(191));

ALTER TABLE vulnerability_cpe_matches
    ADD COLUMN matchCriteriaId CHAR(36) NULL AFTER criteria,
    ADD INDEX idx_vulncpe_match_criteria_id (matchCriteriaId);

CREATE TABLE asset_facts (
    factID BIGINT AUTO_INCREMENT PRIMARY KEY,
    assetID INT NOT NULL,
    factKey VARCHAR(100) NOT NULL,
    factValue VARCHAR(512) NOT NULL,
    source VARCHAR(30) NOT NULL,
    confidence DECIMAL(4,3) NOT NULL DEFAULT 1.000,
    firstSeen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lastSeen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    UNIQUE KEY uq_asset_fact_source (assetID, factKey, source),
    INDEX idx_asset_fact_key (assetID, factKey),
    INDEX idx_asset_fact_freshness (lastSeen)
);

CREATE TABLE asset_platform_cpes (
    platformCpeID BIGINT AUTO_INCREMENT PRIMARY KEY,
    assetID INT NOT NULL,
    cpe VARCHAR(512) NOT NULL,
    source VARCHAR(30) NOT NULL,
    isActive BOOLEAN NOT NULL DEFAULT TRUE,
    firstSeen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lastSeen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    UNIQUE KEY uq_asset_platform_cpe (assetID, cpe, source),
    INDEX idx_platform_active_cpe (isActive, cpe(191)),
    INDEX idx_platform_freshness (lastSeen)
);

CREATE TABLE vulnerability_configurations (
    configurationID BIGINT AUTO_INCREMENT PRIMARY KEY,
    vulnID INT NOT NULL,
    configIndex INT NOT NULL,
    configurationJson LONGTEXT NOT NULL,
    source VARCHAR(30) NOT NULL DEFAULT 'NVD',
    createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (vulnID) REFERENCES vulnerabilities(vulnID) ON DELETE CASCADE,
    UNIQUE KEY uq_vuln_configuration (vulnID, configIndex, source),
    INDEX idx_vuln_configuration_source (vulnID, source)
);
