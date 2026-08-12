USE ctvlms;

-- CTVLMS v3.5: scheduler overlap protection is connection-scoped via a
-- MariaDB named lock; this table records each attempted cycle for operations,
-- troubleshooting, and deployment health without storing secrets.

CREATE TABLE IF NOT EXISTS continuous_cycle_runs (
    cycleRunID BIGINT AUTO_INCREMENT PRIMARY KEY,
    workerID VARCHAR(160) NOT NULL,
    status ENUM('Running','Succeeded','Partial','Failed','Skipped') NOT NULL DEFAULT 'Running',
    startedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completedAt DATETIME,
    summaryJson LONGTEXT,
    errorMessage TEXT,
    INDEX idx_cycle_run_status (status, startedAt),
    INDEX idx_cycle_run_worker (workerID, startedAt),
    INDEX idx_cycle_run_completed (completedAt)
);
