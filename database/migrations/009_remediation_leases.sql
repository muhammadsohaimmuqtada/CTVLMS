USE ctvlms;

-- CTVLMS v3.4: worker fencing, crash recovery, bounded retry scheduling, and
-- optional maintenance windows for package remediation.

ALTER TABLE asset_patch_policies
    ADD COLUMN IF NOT EXISTS sshKnownHostsEnv VARCHAR(100) NULL AFTER sshKeyEnv,
    ADD COLUMN IF NOT EXISTS maintenanceTimezone VARCHAR(64) NOT NULL DEFAULT 'UTC' AFTER sshKnownHostsEnv,
    ADD COLUMN IF NOT EXISTS maintenanceDays VARCHAR(64) NULL AFTER maintenanceTimezone,
    ADD COLUMN IF NOT EXISTS maintenanceStart TIME NULL AFTER maintenanceDays,
    ADD COLUMN IF NOT EXISTS maintenanceEnd TIME NULL AFTER maintenanceStart,
    ADD COLUMN IF NOT EXISTS maxPatchAttempts TINYINT UNSIGNED NOT NULL DEFAULT 3 AFTER maintenanceEnd,
    ADD COLUMN IF NOT EXISTS patchCommandTimeoutSeconds SMALLINT UNSIGNED NOT NULL DEFAULT 1800 AFTER maxPatchAttempts;

ALTER TABLE remediation_jobs
    ADD COLUMN IF NOT EXISTS leaseToken CHAR(64) NULL AFTER status,
    ADD COLUMN IF NOT EXISTS workerID VARCHAR(160) NULL AFTER leaseToken,
    ADD COLUMN IF NOT EXISTS leasedUntil DATETIME NULL AFTER workerID,
    ADD COLUMN IF NOT EXISTS lastHeartbeatAt DATETIME NULL AFTER leasedUntil,
    ADD COLUMN IF NOT EXISTS attemptCount SMALLINT UNSIGNED NOT NULL DEFAULT 0 AFTER lastHeartbeatAt,
    ADD COLUMN IF NOT EXISTS maxAttempts TINYINT UNSIGNED NOT NULL DEFAULT 3 AFTER attemptCount,
    ADD COLUMN IF NOT EXISTS nextAttemptAt DATETIME NULL AFTER maxAttempts,
    ADD COLUMN IF NOT EXISTS lastFailureClass VARCHAR(80) NULL AFTER nextAttemptAt;

ALTER TABLE remediation_jobs
    ADD INDEX IF NOT EXISTS idx_jobs_claimable (status,nextAttemptAt,leasedUntil,requestedAt),
    ADD INDEX IF NOT EXISTS idx_jobs_lease (leaseToken,leasedUntil),
    ADD INDEX IF NOT EXISTS idx_jobs_worker (workerID,status);
