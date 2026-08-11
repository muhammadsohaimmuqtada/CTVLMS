USE ctvlms;

-- Authoritative Linux package identity and distribution advisory intelligence.
-- Package names and versions intentionally remain separate from CPE/product data.

CREATE TABLE IF NOT EXISTS asset_package_inventory (
    packageInventoryID BIGINT AUTO_INCREMENT PRIMARY KEY,
    softwareID BIGINT NOT NULL,
    assetID INT NOT NULL,
    binaryPackage VARCHAR(200) NOT NULL,
    binaryVersion VARCHAR(255) NOT NULL,
    architecture VARCHAR(40) NOT NULL,
    sourcePackage VARCHAR(200),
    sourceVersion VARCHAR(255),
    upstreamSourceVersion VARCHAR(255),
    packageManager VARCHAR(30) NOT NULL,
    inventorySource VARCHAR(50) NOT NULL,
    identityAuthoritative BOOLEAN NOT NULL DEFAULT FALSE,
    isActive BOOLEAN NOT NULL DEFAULT TRUE,
    firstSeen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lastSeen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (softwareID) REFERENCES asset_software(softwareID) ON DELETE CASCADE,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    UNIQUE KEY uq_package_inventory_identity
        (assetID, binaryPackage, architecture, packageManager, inventorySource),
    UNIQUE KEY uq_package_inventory_software (softwareID),
    INDEX idx_package_source_correlation (sourcePackage, sourceVersion),
    INDEX idx_package_asset_active (assetID, isActive),
    INDEX idx_package_binary_version (binaryPackage, binaryVersion)
);

CREATE TABLE IF NOT EXISTS distribution_advisories (
    advisoryID BIGINT AUTO_INCREMENT PRIMARY KEY,
    recordKey CHAR(64) NOT NULL,
    advisoryIdentifier VARCHAR(100),
    cveID VARCHAR(30) NOT NULL,
    distribution VARCHAR(50) NOT NULL,
    suite VARCHAR(80) NOT NULL,
    sourcePackage VARCHAR(200) NOT NULL,
    state ENUM('Vulnerable','Fixed','Not_Affected','Unknown') NOT NULL,
    fixedVersion VARCHAR(255),
    urgency VARCHAR(50),
    severity VARCHAR(50),
    upstreamReference TEXT,
    sourceUrl VARCHAR(1024) NOT NULL,
    dataSourceIdentifier VARCHAR(160) NOT NULL,
    provider VARCHAR(100) NOT NULL,
    lastSyncRunID BIGINT,
    providerRecordJson LONGTEXT,
    upstreamUpdatedAt DATETIME,
    firstSyncedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lastSyncedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_distribution_advisory_record (recordKey),
    INDEX idx_advisory_source_suite (distribution, suite, sourcePackage),
    INDEX idx_advisory_cve (cveID),
    INDEX idx_advisory_fixed_version (sourcePackage, fixedVersion),
    INDEX idx_advisory_provider_sync (provider, lastSyncedAt)
);

CREATE TABLE IF NOT EXISTS distribution_advisory_sync_runs (
    syncRunID BIGINT AUTO_INCREMENT PRIMARY KEY,
    provider VARCHAR(100) NOT NULL,
    dataSourceIdentifier VARCHAR(160) NOT NULL,
    sourceUrl VARCHAR(1024) NOT NULL,
    status ENUM('Running','Succeeded','Failed') NOT NULL DEFAULT 'Running',
    recordsProcessed INT NOT NULL DEFAULT 0,
    recordsStored INT NOT NULL DEFAULT 0,
    startedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completedAt DATETIME,
    errorMessage TEXT,
    INDEX idx_advisory_sync_provider (provider, startedAt)
);

CREATE TABLE IF NOT EXISTS package_evaluation_state (
    packageInventoryID BIGINT PRIMARY KEY,
    outcome ENUM('Confirmed','Not_Affected','Unknown','Unmapped') NOT NULL,
    advisoryCoverage BOOLEAN NOT NULL DEFAULT FALSE,
    provider VARCHAR(100),
    evidence TEXT,
    evaluatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (packageInventoryID) REFERENCES asset_package_inventory(packageInventoryID) ON DELETE CASCADE,
    INDEX idx_package_evaluation_outcome (outcome, advisoryCoverage, evaluatedAt)
);

CREATE TABLE IF NOT EXISTS package_exposure_advisories (
    exposureID BIGINT PRIMARY KEY,
    advisoryID BIGINT NOT NULL,
    FOREIGN KEY (exposureID) REFERENCES exposure_matches(exposureID) ON DELETE CASCADE,
    FOREIGN KEY (advisoryID) REFERENCES distribution_advisories(advisoryID) ON DELETE CASCADE,
    INDEX idx_package_exposure_advisory (advisoryID)
);

ALTER TABLE exposure_matches
    MODIFY COLUMN matchType ENUM(
        'CPE_Exact','CPE_Range','CPE_Potential','Package_Advisory','Manual'
    ) NOT NULL;
