#!/usr/bin/env php
<?php
/**
 * CTVLMS — Policy-gated package remediation worker.
 *
 * Executes one queued/approved package upgrade per invocation. It is purposely
 * not a generic remote shell: only validated package names and fixed commands
 * for supported package managers are allowed.
 */

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/audit.php';
require_once __DIR__ . '/../includes/exposure.php';

function runSsh(array $job, string $remoteCommand): array
{
    $ip = (string)$job['ipAddress'];
    $user = (string)$job['sshUser'];
    $keyEnv = (string)$job['sshKeyEnv'];

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        throw new RuntimeException('Patch target does not have a valid IP address.');
    }
    if (!preg_match('/^[A-Za-z0-9._-]+$/', $user)) {
        throw new RuntimeException('Invalid SSH user configured for asset.');
    }
    if (!preg_match('/^[A-Z_][A-Z0-9_]*$/', $keyEnv)) {
        throw new RuntimeException('SSH key environment reference is invalid.');
    }

    $keyPath = trim((string)getenv($keyEnv));
    if ($keyPath === '' || !is_file($keyPath)) {
        throw new RuntimeException("SSH key file referenced by {$keyEnv} is unavailable.");
    }

    $cmd = [
        'ssh',
        '-i', $keyPath,
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=10',
        '-o', 'StrictHostKeyChecking=yes',
        $user . '@' . $ip,
        $remoteCommand,
    ];

    $descriptor = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $proc = proc_open($cmd, $descriptor, $pipes);
    if (!is_resource($proc)) {
        throw new RuntimeException('Unable to launch SSH client.');
    }

    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exit = proc_close($proc);

    return ['exit' => $exit, 'stdout' => trim($stdout), 'stderr' => trim($stderr)];
}

function packageCommands(string $manager, string $package): array
{
    if (!preg_match('/^[A-Za-z0-9.+:_-]+$/', $package)) {
        throw new RuntimeException('Package name failed validation.');
    }

    return match ($manager) {
        'apt' => [
            "dpkg-query -W -f='\${Version}' {$package}",
            "sudo -n apt-get update && sudo -n apt-get install --only-upgrade -y {$package}",
        ],
        'dnf' => [
            "rpm -q --qf '%{VERSION}-%{RELEASE}' {$package}",
            "sudo -n dnf -y upgrade {$package}",
        ],
        'yum' => [
            "rpm -q --qf '%{VERSION}-%{RELEASE}' {$package}",
            "sudo -n yum -y update {$package}",
        ],
        'apk' => [
            "apk info -v {$package} | head -n 1",
            "sudo -n apk upgrade {$package}",
        ],
        default => throw new RuntimeException('Unsupported package manager.'),
    };
}

$db = getDB();
$db->beginTransaction();
try {
    $stmt = $db->query(
        "SELECT j.*, a.ipAddress, p.mode, p.transport, p.sshUser, p.sshKeyEnv,
                p.requireVerifiedBackup, s.version AS inventoryVersion
         FROM remediation_jobs j
         JOIN assets a ON a.assetID = j.assetID
         JOIN asset_patch_policies p ON p.assetID = j.assetID
         JOIN asset_software s ON s.softwareID = j.softwareID
         WHERE j.status IN ('Queued','Approved')
         ORDER BY j.requestedAt ASC
         LIMIT 1
         FOR UPDATE"
    );
    $job = $stmt->fetch();

    if (!$job) {
        $db->commit();
        echo "No executable remediation jobs.\n";
        exit(0);
    }

    if ($job['status'] === 'Queued' && $job['mode'] !== 'Auto') {
        throw new RuntimeException('Queued job is not permitted by current Auto policy.');
    }
    if ($job['transport'] !== 'SSH') {
        throw new RuntimeException('This worker currently supports SSH-managed assets only.');
    }
    if ((bool)$job['requireVerifiedBackup'] && !assetHasValidBackupEvidence($db, (int)$job['assetID'])) {
        throw new RuntimeException('Verified backup evidence is required before patch execution.');
    }

    $claim = $db->prepare(
        "UPDATE remediation_jobs
         SET status = 'Running', startedAt = CURRENT_TIMESTAMP, lastError = NULL
         WHERE jobID = :id"
    );
    $claim->execute([':id' => $job['jobID']]);
    $markExposure = $db->prepare("UPDATE exposure_matches SET status = 'Remediating' WHERE exposureID = :id");
    $markExposure->execute([':id' => $job['exposureID']]);
    $db->commit();
} catch (Throwable $ex) {
    if ($db->inTransaction()) $db->rollBack();
    fwrite(STDERR, "Unable to claim remediation job: {$ex->getMessage()}\n");
    exit(1);
}

try {
    [$versionCommand, $upgradeCommand] = packageCommands($job['packageManager'], $job['packageName']);

    $before = runSsh($job, $versionCommand);
    if ($before['exit'] !== 0 || $before['stdout'] === '') {
        throw new RuntimeException('Unable to determine installed package version: ' . ($before['stderr'] ?: 'unknown error'));
    }

    $upgrade = runSsh($job, $upgradeCommand);
    if ($upgrade['exit'] !== 0) {
        throw new RuntimeException('Package upgrade failed: ' . ($upgrade['stderr'] ?: $upgrade['stdout']));
    }

    $after = runSsh($job, $versionCommand);
    if ($after['exit'] !== 0 || $after['stdout'] === '') {
        throw new RuntimeException('Unable to verify package version after upgrade: ' . ($after['stderr'] ?: 'unknown error'));
    }

    $beforeVersion = trim(explode("\n", $before['stdout'])[0]);
    $afterVersion = trim(explode("\n", $after['stdout'])[0]);
    if ($beforeVersion === $afterVersion) {
        throw new RuntimeException('Upgrade command completed but installed version did not change.');
    }

    $evidence = json_encode([
        'package' => $job['packageName'],
        'package_manager' => $job['packageManager'],
        'before_version' => $beforeVersion,
        'after_version' => $afterVersion,
        'transport' => 'SSH',
        'completed_at' => gmdate(DATE_ATOM),
    ], JSON_UNESCAPED_SLASHES);

    $db->beginTransaction();
    $finish = $db->prepare(
        "UPDATE remediation_jobs
         SET status = 'Succeeded', fromVersion = :before, targetVersion = :after,
             completedAt = CURRENT_TIMESTAMP, verificationEvidence = :evidence
         WHERE jobID = :id"
    );
    $finish->execute([
        ':before' => $beforeVersion,
        ':after' => $afterVersion,
        ':evidence' => $evidence,
        ':id' => $job['jobID'],
    ]);

    $software = $db->prepare(
        'UPDATE asset_software SET version = :version, lastSeen = CURRENT_TIMESTAMP WHERE softwareID = :id'
    );
    $software->execute([':version' => $afterVersion, ':id' => $job['softwareID']]);

    $exposure = $db->prepare("UPDATE exposure_matches SET status = 'Remediated' WHERE exposureID = :id");
    $exposure->execute([':id' => $job['exposureID']]);

    $lifecycle = $db->prepare(
        "UPDATE asset_vulnerabilities av
         JOIN exposure_matches e ON e.assetID = av.assetID AND e.vulnID = av.vulnID
         SET av.status = 'Remediated'
         WHERE e.exposureID = :exposure
           AND av.status IN ('Confirmed','Remediation_In_Progress')"
    );
    $lifecycle->execute([':exposure' => $job['exposureID']]);

    logAction('AUTO_PATCH', 'remediation_jobs', (int)$job['jobID'], "Upgraded {$job['packageName']} {$beforeVersion} → {$afterVersion}");
    $db->commit();

    echo "Patched job #{$job['jobID']}: {$job['packageName']} {$beforeVersion} -> {$afterVersion}\n";
} catch (Throwable $ex) {
    if ($db->inTransaction()) $db->rollBack();

    $fail = $db->prepare(
        "UPDATE remediation_jobs
         SET status = 'Failed', completedAt = CURRENT_TIMESTAMP, lastError = :error
         WHERE jobID = :id"
    );
    $fail->execute([':error' => $ex->getMessage(), ':id' => $job['jobID']]);
    $restore = $db->prepare("UPDATE exposure_matches SET status = 'Confirmed' WHERE exposureID = :id");
    $restore->execute([':id' => $job['exposureID']]);
    logAction('PATCH_FAILED', 'remediation_jobs', (int)$job['jobID'], $ex->getMessage());

    fwrite(STDERR, "Patch job #{$job['jobID']} failed: {$ex->getMessage()}\n");
    exit(1);
}
