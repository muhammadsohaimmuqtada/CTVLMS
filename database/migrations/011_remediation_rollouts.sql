USE ctvlms;

-- CTVLMS v3.6: staged/canary remediation rollout controls.
-- Assets are optionally assigned to a rollout group. Unassigned assets retain
-- current behaviour. Canary selection is deterministic per group/asset and
-- promotion to General is an explicit operator action.

CREATE TABLE IF NOT EXISTS remediation_rollout_groups (
    groupID BIGINT AUTO_INCREMENT PRIMARY KEY,
    groupName VARCHAR(120) NOT NULL,
    phase ENUM('Canary','General','Paused') NOT NULL DEFAULT 'Canary',
    canaryPercent TINYINT UNSIGNED NOT NULL DEFAULT 10,
    maxConcurrent SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    autoPauseOnFailure BOOLEAN NOT NULL DEFAULT TRUE,
    failureThreshold SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    pausedReason VARCHAR(500) NULL,
    createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_rollout_group_name (groupName),
    INDEX idx_rollout_phase (phase, updatedAt)
);

CREATE TABLE IF NOT EXISTS asset_remediation_rollouts (
    assetID INT PRIMARY KEY,
    groupID BIGINT NOT NULL,
    assignedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    FOREIGN KEY (groupID) REFERENCES remediation_rollout_groups(groupID) ON DELETE CASCADE,
    INDEX idx_asset_rollout_group (groupID, assetID)
);

CREATE TABLE IF NOT EXISTS remediation_rollout_events (
    eventID BIGINT AUTO_INCREMENT PRIMARY KEY,
    groupID BIGINT NOT NULL,
    assetID INT NULL,
    jobID BIGINT NULL,
    eventType ENUM('Created','Assigned','Phase_Changed','Deferred','Succeeded','Failed','Auto_Paused') NOT NULL,
    details VARCHAR(1000) NULL,
    createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (groupID) REFERENCES remediation_rollout_groups(groupID) ON DELETE CASCADE,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE SET NULL,
    FOREIGN KEY (jobID) REFERENCES remediation_jobs(jobID) ON DELETE SET NULL,
    INDEX idx_rollout_events_group_time (groupID, createdAt),
    INDEX idx_rollout_events_job (jobID)
);
