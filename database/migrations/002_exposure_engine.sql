USE ctvlms;

-- CTVLMS v2 exposure engine.
-- Raw observations are kept separate from vulnerability applicability and
-- remediation execution so every automated decision has traceable evidence.

CREATE TABLE IF NOT EXISTS scan_runs (
    scanRunID BIGINT AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    scanner VARCHAR(50) NOT NULL DEFAULT 'nmap',
    status ENUM('Running','Succeeded','Failed') NOT NULL DEFAULT 'Running',
    hostsObserved INT NOT NULL DEFAULT 0,
    startedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completedAt DATETIME,
    errorMessage TEXT
);

CREATE TABLE IF NOT EXISTS asset_services (
    serviceID BIGINT AUTO_INCREMENT PRIMARY KEY,
    assetID INT NOT NULL,
    protocol ENUM('tcp','udp') NOT NULL,
    port INT NOT NULL,
    state VARCHAR(30),
    serviceName VARCHAR(100),
    product VARCHAR(200),
    version VARCHAR(120),
    cpe VARCHAR(512),
    firstSeen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lastSeen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    UNIQUE KEY uq_asset_service (assetID, protocol, port),
    INDEX idx_service_cpe (cpe(191)),
    INDEX idx_service_last_seen (lastSeen)
);

CREATE TABLE IF NOT EXISTS asset_software (
    softwareID BIGINT AUTO_INCREMENT PRIMARY KEY,
    assetID INT NOT NULL,
    vendor VARCHAR(160),
    product VARCHAR(200) NOT NULL,
    version VARCHAR(120),
    cpe VARCHAR(512),
    packageManager ENUM('apt','dnf','yum','apk','none') NOT NULL DEFAULT 'none',
    packageName VARCHAR(200),
    source ENUM('Agent','Manual','Scanner') NOT NULL DEFAULT 'Manual',
    firstSeen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lastSeen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    UNIQUE KEY uq_asset_software (assetID, product, version, packageName),
    INDEX idx_software_cpe (cpe(191)),
    INDEX idx_software_package (packageName)
);

CREATE TABLE IF NOT EXISTS vulnerability_cpe_matches (
    vulnCpeID BIGINT AUTO_INCREMENT PRIMARY KEY,
    vulnID INT NOT NULL,
    criteria VARCHAR(512) NOT NULL,
    vulnerable BOOLEAN NOT NULL DEFAULT TRUE,
    configurationComplex BOOLEAN NOT NULL DEFAULT FALSE,
    versionStartIncluding VARCHAR(120),
    versionStartExcluding VARCHAR(120),
    versionEndIncluding VARCHAR(120),
    versionEndExcluding VARCHAR(120),
    source VARCHAR(30) NOT NULL DEFAULT 'NVD',
    FOREIGN KEY (vulnID) REFERENCES vulnerabilities(vulnID) ON DELETE CASCADE,
    INDEX idx_vulncpe_vuln (vulnID),
    INDEX idx_vulncpe_criteria (criteria(191))
);

CREATE TABLE IF NOT EXISTS exposure_matches (
    exposureID BIGINT AUTO_INCREMENT PRIMARY KEY,
    matchKey CHAR(64) NOT NULL UNIQUE,
    assetID INT NOT NULL,
    vulnID INT NOT NULL,
    softwareID BIGINT,
    serviceID BIGINT,
    matchType ENUM('CPE_Exact','CPE_Range','CPE_Potential','Manual') NOT NULL,
    confidence DECIMAL(4,3) NOT NULL,
    status ENUM('Potential','Confirmed','Not_Affected','Remediation_Queued','Remediating','Remediated','Verification_Failed','Verified_Closed') NOT NULL DEFAULT 'Potential',
    evidence TEXT,
    firstSeen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lastEvaluated DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    FOREIGN KEY (vulnID) REFERENCES vulnerabilities(vulnID) ON DELETE CASCADE,
    FOREIGN KEY (softwareID) REFERENCES asset_software(softwareID) ON DELETE SET NULL,
    FOREIGN KEY (serviceID) REFERENCES asset_services(serviceID) ON DELETE SET NULL,
    INDEX idx_exposure_asset_status (assetID, status),
    INDEX idx_exposure_vuln (vulnID),
    INDEX idx_exposure_evaluated (lastEvaluated)
);

CREATE TABLE IF NOT EXISTS asset_patch_policies (
    assetID INT PRIMARY KEY,
    mode ENUM('Disabled','Approval','Auto') NOT NULL DEFAULT 'Approval',
    allowMajorUpgrade BOOLEAN NOT NULL DEFAULT FALSE,
    allowReboot BOOLEAN NOT NULL DEFAULT FALSE,
    requireVerifiedBackup BOOLEAN NOT NULL DEFAULT TRUE,
    transport ENUM('None','SSH','Agent') NOT NULL DEFAULT 'None',
    sshUser VARCHAR(100),
    sshKeyEnv VARCHAR(100),
    updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS asset_backup_evidence (
    assetID INT PRIMARY KEY,
    source VARCHAR(100) NOT NULL,
    referenceValue VARCHAR(255),
    lastVerifiedAt DATETIME NOT NULL,
    validUntil DATETIME,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    INDEX idx_backup_validity (validUntil)
);

CREATE TABLE IF NOT EXISTS remediation_jobs (
    jobID BIGINT AUTO_INCREMENT PRIMARY KEY,
    exposureID BIGINT NOT NULL,
    assetID INT NOT NULL,
    softwareID BIGINT,
    jobType ENUM('Package_Upgrade') NOT NULL DEFAULT 'Package_Upgrade',
    packageManager ENUM('apt','dnf','yum','apk') NOT NULL,
    packageName VARCHAR(200) NOT NULL,
    fromVersion VARCHAR(120),
    targetVersion VARCHAR(120),
    status ENUM('Queued','Awaiting_Approval','Approved','Running','Succeeded','Failed','Rollback_Running','Rolled_Back','Rollback_Failed') NOT NULL DEFAULT 'Queued',
    requestedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approvedByUserID INT,
    approvedAt DATETIME,
    startedAt DATETIME,
    completedAt DATETIME,
    lastError TEXT,
    verificationEvidence TEXT,
    FOREIGN KEY (exposureID) REFERENCES exposure_matches(exposureID) ON DELETE CASCADE,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    FOREIGN KEY (softwareID) REFERENCES asset_software(softwareID) ON DELETE SET NULL,
    FOREIGN KEY (approvedByUserID) REFERENCES users(userID) ON DELETE SET NULL,
    INDEX idx_jobs_status_requested (status, requestedAt)
);
