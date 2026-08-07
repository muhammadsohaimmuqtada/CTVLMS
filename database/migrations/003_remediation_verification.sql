USE ctvlms;

CREATE TABLE remediation_verifications (
    verificationID BIGINT AUTO_INCREMENT PRIMARY KEY,
    remediationID INT NOT NULL UNIQUE,
    verifierType ENUM('Human','Automated') NOT NULL,
    verifiedByUserID INT,
    evidence TEXT NOT NULL,
    verifiedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (remediationID) REFERENCES remediations(remediationID) ON DELETE CASCADE,
    FOREIGN KEY (verifiedByUserID) REFERENCES users(userID) ON DELETE SET NULL
);

ALTER TABLE remediation_jobs
    ADD COLUMN remediationID INT NULL AFTER softwareID,
    ADD CONSTRAINT fk_job_remediation
        FOREIGN KEY (remediationID) REFERENCES remediations(remediationID) ON DELETE SET NULL;
