USE ctvlms;

-- Track whether each vulnerability has been refreshed through the v3 NVD
-- importer. This distinguishes "not yet backfilled" from a legitimate NVD CVE
-- that contains no applicability configuration.
ALTER TABLE vulnerabilities
    ADD COLUMN nvdLastSyncedAt DATETIME NULL AFTER publishedDate,
    ADD COLUMN nvdConfigurationState ENUM('Unknown','Present','None') NOT NULL DEFAULT 'Unknown' AFTER nvdLastSyncedAt,
    ADD INDEX idx_vuln_nvd_configuration_state (nvdConfigurationState, nvdLastSyncedAt);
