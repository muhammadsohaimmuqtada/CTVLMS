<?php
/**
 * Guardrails and reporting for the first real Debian design-partner/staging fleet.
 *
 * This module is intentionally read-only. It never approves or executes remediation.
 */

function parseStagingAssetIDs(string $raw): array
{
    $parts = array_values(array_filter(array_map('trim', explode(',', $raw)), static fn(string $v): bool => $v !== ''));
    $ids = [];
    foreach ($parts as $part) {
        if (!preg_match('/^[1-9][0-9]*$/', $part)) {
            throw new InvalidArgumentException('Staging asset IDs must be positive integers.');
        }
        $ids[(int)$part] = true;
    }
    $ids = array_keys($ids);
    sort($ids, SORT_NUMERIC);
    if (count($ids) < 2 || count($ids) > 3) {
        throw new InvalidArgumentException('The first real staging fleet must contain exactly 2 or 3 unique assets.');
    }
    return $ids;
}

function isValidStagingEnvReference(?string $value): bool
{
    return is_string($value) && preg_match('/^[A-Z_][A-Z0-9_]*$/', $value) === 1;
}

function stagingPlaceholders(array $ids, string $prefix = 'asset'): array
{
    $holders = [];
    $params = [];
    foreach (array_values($ids) as $index => $id) {
        $key = ':' . $prefix . $index;
        $holders[] = $key;
        $params[$key] = (int)$id;
    }
    return [$holders, $params];
}

function stagingFleetRows(PDO $db, array $assetIDs): array
{
    [$holders, $params] = stagingPlaceholders($assetIDs);
    $sql = "SELECT
                a.assetID,a.assetName,a.ipAddress,a.environment,a.osPlatform,
                i.mode AS inventoryMode,i.sshUser AS inventorySshUser,i.sshKeyEnv AS inventorySshKeyEnv,
                i.knownHostsEnv AS inventoryKnownHostsEnv,i.connectTimeoutSeconds,
                p.mode AS patchMode,p.transport AS patchTransport,p.sshUser AS patchSshUser,
                p.sshKeyEnv AS patchSshKeyEnv,p.sshKnownHostsEnv AS patchKnownHostsEnv,
                p.allowMajorUpgrade,p.allowReboot,p.requireVerifiedBackup,
                p.maintenanceTimezone,p.maintenanceDays,p.maintenanceStart,p.maintenanceEnd,
                p.maxPatchAttempts,p.patchCommandTimeoutSeconds,
                b.source AS backupSource,b.referenceValue AS backupReference,b.lastVerifiedAt,b.validUntil,
                (SELECT ir.status FROM inventory_runs ir WHERE ir.assetID=a.assetID ORDER BY ir.inventoryRunID DESC LIMIT 1) AS latestInventoryStatus,
                (SELECT ir.completedAt FROM inventory_runs ir WHERE ir.assetID=a.assetID AND ir.status='Succeeded' ORDER BY ir.inventoryRunID DESC LIMIT 1) AS latestSuccessfulInventoryAt,
                (SELECT COUNT(*) FROM remediation_jobs rj WHERE rj.assetID=a.assetID AND rj.status='Running') AS runningJobs
            FROM assets a
            LEFT JOIN asset_inventory_policies i ON i.assetID=a.assetID
            LEFT JOIN asset_patch_policies p ON p.assetID=a.assetID
            LEFT JOIN asset_backup_evidence b ON b.assetID=a.assetID
            WHERE a.assetID IN (" . implode(',', $holders) . ")
            ORDER BY a.assetID";
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function stagingPrepareAssessment(PDO $db, array $assetIDs): array
{
    $rows = stagingFleetRows($db, $assetIDs);
    $byID = [];
    foreach ($rows as $row) $byID[(int)$row['assetID']] = $row;

    $errors = [];
    $warnings = [];
    if ((string)getenv('CTVLMS_EXECUTE_PATCHES') === '1') {
        $errors[] = 'CTVLMS_EXECUTE_PATCHES must remain disabled during staging preparation.';
    }

    foreach ($assetIDs as $assetID) {
        if (!isset($byID[$assetID])) {
            $errors[] = "Asset {$assetID} does not exist.";
            continue;
        }
        $row = $byID[$assetID];
        $name = (string)$row['assetName'];
        if (($row['environment'] ?? '') !== 'Staging') $errors[] = "{$name}: environment must be Staging.";
        if (empty($row['ipAddress'])) $errors[] = "{$name}: an explicit IP address is required.";
        if (($row['inventoryMode'] ?? '') !== 'SSH') $errors[] = "{$name}: managed inventory mode must be SSH.";
        if (!preg_match('/^[A-Za-z0-9._-]+$/', (string)($row['inventorySshUser'] ?? ''))) $errors[] = "{$name}: inventory SSH user is invalid.";
        if (!isValidStagingEnvReference($row['inventorySshKeyEnv'] ?? null)) $errors[] = "{$name}: inventory SSH key environment reference is invalid.";
        if (!isValidStagingEnvReference($row['inventoryKnownHostsEnv'] ?? null)) $errors[] = "{$name}: inventory known-hosts environment reference is invalid.";

        if (($row['patchMode'] ?? '') !== 'Approval') $errors[] = "{$name}: patch mode must be Approval for the first real staging fleet.";
        if (($row['patchTransport'] ?? '') !== 'SSH') $errors[] = "{$name}: patch transport must be SSH.";
        if (!preg_match('/^[A-Za-z0-9._-]+$/', (string)($row['patchSshUser'] ?? ''))) $errors[] = "{$name}: patch SSH user is invalid.";
        if (!isValidStagingEnvReference($row['patchSshKeyEnv'] ?? null)) $errors[] = "{$name}: patch SSH key environment reference is invalid.";
        if (!isValidStagingEnvReference($row['patchKnownHostsEnv'] ?? null)) $errors[] = "{$name}: patch known-hosts environment reference is invalid.";
        if ((int)($row['requireVerifiedBackup'] ?? 0) !== 1) $errors[] = "{$name}: verified backup gate must be enabled.";
        if ((int)($row['allowMajorUpgrade'] ?? 0) !== 0) $errors[] = "{$name}: major upgrades must be disabled for the first pilot.";
        if ((int)($row['allowReboot'] ?? 0) !== 0) $errors[] = "{$name}: automatic reboot must be disabled for the first pilot.";
        if ((int)($row['runningJobs'] ?? 0) !== 0) $errors[] = "{$name}: an existing remediation job is already Running.";

        $validUntil = $row['validUntil'] ?? null;
        if (empty($row['backupSource']) || ($validUntil !== null && strtotime((string)$validUntil) < time())) {
            $warnings[] = "{$name}: no currently valid backup evidence is recorded yet; patch execution will remain blocked.";
        }
        if (($row['latestInventoryStatus'] ?? null) !== 'Succeeded') {
            $warnings[] = "{$name}: no latest successful managed inventory is recorded yet.";
        }
    }

    return [
        'ok' => $errors === [],
        'phase' => 'prepare',
        'asset_ids' => array_values($assetIDs),
        'errors' => $errors,
        'warnings' => $warnings,
        'assets' => array_values($rows),
    ];
}

function stagingExecutionAssessment(PDO $db, array $assetIDs, int $jobID): array
{
    $prepare = stagingPrepareAssessment($db, $assetIDs);
    $errors = $prepare['errors'];
    $warnings = $prepare['warnings'];

    if ((string)getenv('CTVLMS_EXECUTE_PATCHES') !== '1') {
        $errors[] = 'CTVLMS_EXECUTE_PATCHES must be explicitly set to 1 only for the approved maintenance-window execution.';
    } else {
        // Preparation intentionally treats enabled execution as an error; remove only that expected phase-specific message.
        $errors = array_values(array_filter($errors, static fn(string $e): bool => $e !== 'CTVLMS_EXECUTE_PATCHES must remain disabled during staging preparation.'));
    }

    [$holders, $params] = stagingPlaceholders($assetIDs);
    $params[':job'] = $jobID;
    $stmt = $db->prepare(
        "SELECT j.jobID,j.assetID,j.status,j.packageManager,j.packageName,j.fromVersion,j.targetVersion,
                e.status AS exposureStatus,a.assetName,p.mode,p.transport,p.requireVerifiedBackup,
                b.source AS backupSource,b.validUntil
         FROM remediation_jobs j
         JOIN exposure_matches e ON e.exposureID=j.exposureID
         JOIN assets a ON a.assetID=j.assetID
         JOIN asset_patch_policies p ON p.assetID=j.assetID
         LEFT JOIN asset_backup_evidence b ON b.assetID=j.assetID
         WHERE j.jobID=:job AND j.assetID IN (" . implode(',', $holders) . ") LIMIT 1"
    );
    $stmt->execute($params);
    $job = $stmt->fetch();
    if (!$job) {
        $errors[] = 'Approved job does not exist in the explicitly selected staging fleet.';
    } else {
        if (($job['status'] ?? '') !== 'Approved') $errors[] = 'The selected job must be explicitly Approved before execution.';
        if (($job['mode'] ?? '') !== 'Approval') $errors[] = 'The selected asset is no longer in Approval mode.';
        if (($job['transport'] ?? '') !== 'SSH') $errors[] = 'The selected asset is no longer using SSH patch transport.';
        if (($job['exposureStatus'] ?? '') !== 'Remediation_Queued') $errors[] = 'The selected exposure is not in Remediation_Queued state.';
        if ((int)($job['requireVerifiedBackup'] ?? 0) !== 1 || empty($job['backupSource'])) $errors[] = 'Verified backup evidence is missing for the selected job.';
        if (($job['validUntil'] ?? null) !== null && strtotime((string)$job['validUntil']) < time()) $errors[] = 'Backup evidence expired before execution.';
    }

    $active = $db->prepare(
        "SELECT COUNT(*) FROM remediation_jobs WHERE assetID IN (" . implode(',', $holders) . ") AND status IN ('Approved','Running')"
    );
    $active->execute(array_filter($params, static fn(string $key): bool => $key !== ':job', ARRAY_FILTER_USE_KEY));
    if ((int)$active->fetchColumn() !== 1) {
        $errors[] = 'Exactly one Approved/Running remediation job is permitted across the first staging fleet.';
    }

    return [
        'ok' => $errors === [],
        'phase' => 'execute',
        'asset_ids' => array_values($assetIDs),
        'job_id' => $jobID,
        'errors' => $errors,
        'warnings' => $warnings,
        'job' => $job ?: null,
    ];
}

function stagingFleetReport(PDO $db, array $assetIDs): array
{
    [$holders, $params] = stagingPlaceholders($assetIDs);
    $in = implode(',', $holders);

    $queries = [
        'confirmed_exposures' => "SELECT COUNT(*) FROM exposure_matches WHERE assetID IN ({$in}) AND status='Confirmed'",
        'potential_exposures' => "SELECT COUNT(*) FROM exposure_matches WHERE assetID IN ({$in}) AND status='Potential'",
        'verified_closed' => "SELECT COUNT(*) FROM exposure_matches WHERE assetID IN ({$in}) AND status='Verified_Closed'",
        'awaiting_approval_jobs' => "SELECT COUNT(*) FROM remediation_jobs WHERE assetID IN ({$in}) AND status='Awaiting_Approval'",
        'approved_jobs' => "SELECT COUNT(*) FROM remediation_jobs WHERE assetID IN ({$in}) AND status='Approved'",
        'running_jobs' => "SELECT COUNT(*) FROM remediation_jobs WHERE assetID IN ({$in}) AND status='Running'",
        'failed_jobs' => "SELECT COUNT(*) FROM remediation_jobs WHERE assetID IN ({$in}) AND status='Failed'",
    ];
    $metrics = [];
    foreach ($queries as $name => $sql) {
        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        $metrics[$name] = (int)$stmt->fetchColumn();
    }

    return [
        'asset_ids' => array_values($assetIDs),
        'generated_at_utc' => gmdate('c'),
        'metrics' => $metrics,
        'assets' => stagingFleetRows($db, $assetIDs),
    ];
}
