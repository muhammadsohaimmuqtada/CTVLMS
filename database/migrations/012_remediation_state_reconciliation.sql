USE ctvlms;

-- A remediation job that becomes unnecessary because fresh authoritative
-- evidence says the exposure is Not_Affected is not a failed patch attempt.
ALTER TABLE remediation_jobs
    MODIFY COLUMN status ENUM(
        'Queued','Awaiting_Approval','Approved','Running','Succeeded','Failed',
        'Cancelled','Rollback_Running','Rolled_Back','Rollback_Failed'
    ) NOT NULL DEFAULT 'Queued';

-- Correlation owns applicability, while verification owns the transition out of
-- Remediated/Verification_Failed. Prevent a fresh correlation pass from erasing
-- the verification-pending state before verify-remediations.php can consume the
-- new evidence. A verified exposure remains closed while evidence still says
-- Not_Affected, and reopens to Verification_Failed if applicability contradicts
-- the closure.
DROP TRIGGER IF EXISTS ctvlms_exposure_status_guard;
DELIMITER $$
CREATE TRIGGER ctvlms_exposure_status_guard
BEFORE UPDATE ON exposure_matches
FOR EACH ROW
BEGIN
    IF OLD.status = 'Verified_Closed' THEN
        IF NEW.status = 'Not_Affected' THEN
            SET NEW.status = 'Verified_Closed';
        ELSEIF NEW.status <> 'Verified_Closed' THEN
            SET NEW.status = 'Verification_Failed';
        END IF;
    ELSEIF OLD.status IN ('Remediated','Verification_Failed')
       AND NEW.status IN ('Confirmed','Potential','Not_Affected') THEN
        SET NEW.status = OLD.status;
    END IF;
END$$
DELIMITER ;

-- If verified closure is contradicted, reopen the asset-level lifecycle too.
-- Otherwise the exposure evidence and the operator lifecycle board can disagree.
DROP TRIGGER IF EXISTS ctvlms_reopen_lifecycle_on_verification_failure;
DELIMITER $$
CREATE TRIGGER ctvlms_reopen_lifecycle_on_verification_failure
AFTER UPDATE ON exposure_matches
FOR EACH ROW
BEGIN
    IF OLD.status = 'Verified_Closed' AND NEW.status = 'Verification_Failed' THEN
        UPDATE asset_vulnerabilities
        SET status = 'Confirmed',
            closedDate = NULL,
            notes = CONCAT_WS('\n', NULLIF(notes,''),
                'CTVLMS reopened this lifecycle record because fresh applicability evidence contradicted verified closure.')
        WHERE assetID = NEW.assetID
          AND vulnID = NEW.vulnID
          AND status = 'Verified_Closed';
    END IF;
END$$
DELIMITER ;

-- If correlation resolves an exposure before execution, retire queued/approval
-- work immediately. Running jobs retain lease ownership; the live-version fence
-- remains responsible for refusing stale execution evidence.
DROP TRIGGER IF EXISTS ctvlms_cancel_obsolete_remediation_jobs;
DELIMITER $$
CREATE TRIGGER ctvlms_cancel_obsolete_remediation_jobs
AFTER UPDATE ON exposure_matches
FOR EACH ROW
BEGIN
    IF NEW.status = 'Not_Affected' AND OLD.status <> NEW.status THEN
        UPDATE remediation_jobs
        SET status = 'Cancelled',
            completedAt = COALESCE(completedAt, CURRENT_TIMESTAMP),
            nextAttemptAt = NULL,
            lastError = 'Cancelled because authoritative applicability changed to Not_Affected before execution.',
            lastFailureClass = 'applicability_changed',
            leaseToken = NULL,
            workerID = NULL,
            leasedUntil = NULL,
            lastHeartbeatAt = NULL
        WHERE exposureID = NEW.exposureID
          AND status IN ('Queued','Awaiting_Approval','Approved');
    END IF;
END$$
DELIMITER ;
