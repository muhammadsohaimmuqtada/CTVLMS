<?php
/**
 * CTVLMS — Vulnerability lifecycle policy engine.
 *
 * Centralises state transitions and privileged terminal actions so the UI,
 * CLI workers, and future API all enforce the same rules.
 */

function lifecycleStatuses(): array
{
    return [
        'Discovered',
        'Triaged',
        'Confirmed',
        'Remediation_In_Progress',
        'Remediated',
        'Verified_Closed',
        'Risk_Accepted',
    ];
}

function lifecycleTransitions(): array
{
    return [
        'Discovered'              => ['Discovered', 'Triaged', 'Risk_Accepted'],
        'Triaged'                 => ['Triaged', 'Discovered', 'Confirmed', 'Risk_Accepted'],
        'Confirmed'               => ['Confirmed', 'Triaged', 'Remediation_In_Progress', 'Risk_Accepted'],
        'Remediation_In_Progress' => ['Remediation_In_Progress', 'Confirmed', 'Remediated', 'Risk_Accepted'],
        'Remediated'              => ['Remediated', 'Remediation_In_Progress', 'Verified_Closed'],
        'Verified_Closed'         => ['Verified_Closed', 'Confirmed'],
        'Risk_Accepted'           => ['Risk_Accepted', 'Confirmed'],
    ];
}

function canAcceptRisk(): bool
{
    return in_array($_SESSION['role'] ?? '', ['Admin', 'Vuln_Manager'], true);
}

function canVerifyRemediation(): bool
{
    return in_array($_SESSION['role'] ?? '', ['Admin', 'Vuln_Manager'], true);
}

function hasVerifiedRemediation(PDO $db, int $assetVulnID): bool
{
    $stmt = $db->prepare(
        'SELECT COUNT(*)
         FROM remediations r
         LEFT JOIN remediation_verifications rv ON rv.remediationID = r.remediationID
         WHERE r.assetVulnID = :id
           AND (
                (r.verifiedByUserID IS NOT NULL AND r.verificationDate IS NOT NULL)
                OR rv.verificationID IS NOT NULL
           )'
    );
    $stmt->execute([':id' => $assetVulnID]);
    return (int)$stmt->fetchColumn() > 0;
}

/**
 * Return an error message when a transition is invalid, or null when allowed.
 */
function validateLifecycleTransition(PDO $db, int $assetVulnID, string $oldStatus, string $newStatus, string $notes = ''): ?string
{
    if (!in_array($newStatus, lifecycleStatuses(), true)) {
        return 'Invalid lifecycle status.';
    }

    $allowed = lifecycleTransitions()[$oldStatus] ?? [];
    if (!in_array($newStatus, $allowed, true)) {
        return sprintf(
            'Invalid lifecycle transition: %s → %s.',
            str_replace('_', ' ', $oldStatus),
            str_replace('_', ' ', $newStatus)
        );
    }

    if ($newStatus === 'Risk_Accepted') {
        if (!canAcceptRisk()) {
            return 'Only Admins or Vulnerability Managers can accept risk.';
        }
        if (trim($notes) === '') {
            return 'Risk acceptance requires a justification in Notes.';
        }
    }

    if ($newStatus === 'Verified_Closed' && !hasVerifiedRemediation($db, $assetVulnID)) {
        return 'Verified closure requires a remediation that was explicitly verified by an authorised human or automated verification workflow.';
    }

    return null;
}

function terminalLifecycleStatus(string $status): bool
{
    return in_array($status, ['Verified_Closed', 'Risk_Accepted'], true);
}
