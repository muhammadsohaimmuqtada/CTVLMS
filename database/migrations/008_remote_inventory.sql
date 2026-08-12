USE ctvlms;

-- CTVLMS v3.3: authenticated remote inventory is deliberately separated from
-- patch/remediation credentials so read-only collection can follow least privilege.

CREATE TABLE IF NOT EXISTS asset_inventory_policies (
    assetID INT PRIMARY KEY,
    mode ENUM('Disabled','SSH') NOT NULL DEFAULT 'Disabled',
    sshUser VARCHAR(100),
    sshKeyEnv VARCHAR(100),
    knownHostsEnv VARCHAR(100),
    connectTimeoutSeconds SMALLINT UNSIGNED NOT NULL DEFAULT 10,
    updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    INDEX idx_inventory_policy_mode (mode, updatedAt)
);

CREATE TABLE IF NOT EXISTS inventory_runs (
    inventoryRunID BIGINT AUTO_INCREMENT PRIMARY KEY,
    assetID INT NOT NULL,
    transport ENUM('Local','SSH') NOT NULL,
    inventorySource VARCHAR(50) NOT NULL,
    status ENUM('Running','Succeeded','Failed') NOT NULL DEFAULT 'Running',
    factsObserved INT NOT NULL DEFAULT 0,
    packagesObserved INT NOT NULL DEFAULT 0,
    startedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completedAt DATETIME,
    errorMessage TEXT,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    INDEX idx_inventory_run_asset (assetID, startedAt),
    INDEX idx_inventory_run_status (status, startedAt)
);
