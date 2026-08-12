<?php
/** Remediation worker leasing, maintenance policy, fencing, and bounded retries. */
require_once __DIR__ . '/remediation.php';

function maintenanceDaySet(?string $value): array
{
    if ($value === null || trim($value) === '') return ['mon','tue','wed','thu','fri','sat','sun'];
    $allowed = [];
    foreach (array_filter(array_map('trim', explode(',', strtolower($value)))) as $day) {
        if (!in_array($day,['mon','tue','wed','thu','fri','sat','sun'],true)) {
            throw new InvalidArgumentException('Invalid maintenance day: ' . $day);
        }
        $allowed[$day] = true;
    }
    return array_keys($allowed);
}

function timeToSeconds(string $time): int
{
    if (!preg_match('/^(\d{2}):(\d{2})(?::(\d{2}))?$/',$time,$m)) {
        throw new InvalidArgumentException('Invalid maintenance time.');
    }
    $h=(int)$m[1]; $min=(int)$m[2]; $sec=(int)($m[3] ?? 0);
    if ($h>23 || $min>59 || $sec>59) throw new InvalidArgumentException('Invalid maintenance time.');
    return $h*3600+$min*60+$sec;
}

function maintenanceWindowAllows(array $policy, ?DateTimeImmutable $nowUtc = null): bool
{
    $start = $policy['maintenanceStart'] ?? null;
    $end = $policy['maintenanceEnd'] ?? null;
    if (($start === null || $start === '') && ($end === null || $end === '')) return true;
    if ($start === null || $start === '' || $end === null || $end === '') return false;

    try { $timezone = new DateTimeZone((string)($policy['maintenanceTimezone'] ?? 'UTC')); }
    catch (Throwable) { return false; }
    $nowUtc ??= new DateTimeImmutable('now',new DateTimeZone('UTC'));
    $local = $nowUtc->setTimezone($timezone);
    $startSeconds = timeToSeconds((string)$start);
    $endSeconds = timeToSeconds((string)$end);
    if ($startSeconds === $endSeconds) return false;
    $seconds = ((int)$local->format('H'))*3600 + ((int)$local->format('i'))*60 + (int)$local->format('s');
    $days = maintenanceDaySet($policy['maintenanceDays'] ?? null);
    $today = strtolower($local->format('D'));

    if ($startSeconds < $endSeconds) {
        return in_array($today,$days,true) && $seconds >= $startSeconds && $seconds < $endSeconds;
    }
    if ($seconds >= $startSeconds) return in_array($today,$days,true);
    if ($seconds < $endSeconds) {
        $previous = strtolower($local->modify('-1 day')->format('D'));
        return in_array($previous,$days,true);
    }
    return false;
}

function remediationWorkerID(): string
{
    $configured = trim((string)getenv('CTVLMS_WORKER_ID'));
    if ($configured !== '' && preg_match('/^[A-Za-z0-9._:@-]{1,160}$/',$configured)) return $configured;
    return substr((gethostname() ?: 'worker') . ':' . getmypid(),0,160);
}

function remediationLeaseSeconds(): int
{
    return max(60,min(1800,(int)(getenv('CTVLMS_PATCH_LEASE_SECONDS') ?: 300)));
}

function remediationRetryDelaySeconds(int $attempt): int
{
    $attempt = max(1,min(20,$attempt));
    return min(900,30 * (2 ** min(5,$attempt-1)));
}

function jobHasValidBackupEvidence(PDO $db, int $assetID): bool
{
    $stmt=$db->prepare('SELECT 1 FROM asset_backup_evidence WHERE assetID=:asset AND (validUntil IS NULL OR validUntil>=CURRENT_TIMESTAMP) LIMIT 1');
    $stmt->execute([':asset'=>$assetID]);
    return (bool)$stmt->fetchColumn();
}

function remediationJobPolicyError(array $row, PDO $db): ?string
{
    try { validatePackageName((string)$row['packageName']); }
    catch (Throwable $e) { return $e->getMessage(); }
    if (($row['mode'] ?? 'Disabled') === 'Disabled') return 'Patch policy is disabled.';
    if (($row['transport'] ?? 'None') !== 'SSH') return 'Current worker requires SSH patch transport.';
    if (!preg_match('/^[A-Za-z0-9._-]+$/',(string)$row['sshUser']) || str_starts_with((string)$row['sshUser'],'-')) return 'Invalid SSH user configured for asset.';
    if (!preg_match('/^[A-Z_][A-Z0-9_]*$/',(string)$row['sshKeyEnv'])) return 'SSH key environment reference is invalid.';
    if (!preg_match('/^[A-Z_][A-Z0-9_]*$/',(string)$row['sshKnownHostsEnv'])) return 'SSH known-hosts environment reference is invalid.';
    if (($row['status'] ?? '') === 'Queued' && ($row['mode'] ?? '') !== 'Auto') return 'Queued job is not permitted by current Auto policy.';
    if ((bool)($row['requireVerifiedBackup'] ?? false) && !jobHasValidBackupEvidence($db,(int)$row['assetID'])) return 'Verified backup evidence is required before patch execution.';
    if (($row['matchType'] ?? '') === 'Package_Advisory' &&
        (!(bool)($row['identityAuthoritative'] ?? false) || ($row['binaryPackage'] ?? null) !== ($row['packageName'] ?? null) ||
         ($row['identityPackageManager'] ?? null) !== ($row['packageManager'] ?? null) || empty($row['advisoryID']))) {
        return 'Authoritative package/advisory identity is required for package-advisory remediation.';
    }
    return null;
}

function claimRemediationJob(PDO $db, ?string $workerID = null, ?int $leaseSeconds = null): ?array
{
    $workerID ??= remediationWorkerID();
    $leaseSeconds ??= remediationLeaseSeconds();
    $leaseSeconds=max(60,min(1800,$leaseSeconds));
    $db->beginTransaction();
    try {
        $stmt=$db->query(
            "SELECT j.*,a.ipAddress,p.mode,p.transport,p.sshUser,p.sshKeyEnv,p.sshKnownHostsEnv,
                    p.requireVerifiedBackup,p.maintenanceTimezone,p.maintenanceDays,p.maintenanceStart,p.maintenanceEnd,
                    p.maxPatchAttempts,p.patchCommandTimeoutSeconds,
                    s.version AS inventoryVersion,e.matchType,e.status AS exposureStatus,
                    av.assetVulnID,av.status AS lifecycleStatus,
                    pi.identityAuthoritative,pi.binaryPackage,pi.packageManager AS identityPackageManager,
                    da.advisoryID
             FROM remediation_jobs j
             JOIN assets a ON a.assetID=j.assetID
             JOIN asset_patch_policies p ON p.assetID=j.assetID
             JOIN asset_software s ON s.softwareID=j.softwareID AND s.isActive=1
             JOIN exposure_matches e ON e.exposureID=j.exposureID
             LEFT JOIN asset_package_inventory pi ON pi.softwareID=s.softwareID AND pi.isActive=1
             LEFT JOIN package_exposure_advisories pea ON pea.exposureID=e.exposureID
             LEFT JOIN distribution_advisories da ON da.advisoryID=pea.advisoryID
             JOIN asset_vulnerabilities av ON av.assetID=e.assetID AND av.vulnID=e.vulnID
             WHERE (
                    (j.status IN ('Queued','Approved') AND (j.nextAttemptAt IS NULL OR j.nextAttemptAt<=CURRENT_TIMESTAMP))
                 OR (j.status='Running' AND j.leasedUntil IS NOT NULL AND j.leasedUntil<CURRENT_TIMESTAMP)
             )
               AND j.attemptCount < LEAST(j.maxAttempts,p.maxPatchAttempts)
               AND e.status IN ('Remediation_Queued','Remediating','Verification_Failed')
             ORDER BY CASE WHEN j.status='Running' THEN 0 ELSE 1 END,j.requestedAt ASC
             LIMIT 25 FOR UPDATE"
        );
        $rows=$stmt->fetchAll();
        foreach ($rows as $row) {
            if (!maintenanceWindowAllows($row)) continue;
            $policyError=remediationJobPolicyError($row,$db);
            if ($policyError!==null) {
                $db->prepare('UPDATE remediation_jobs SET lastError=:error,lastFailureClass=\'policy_blocked\' WHERE jobID=:id')
                    ->execute([':error'=>$policyError,':id'=>$row['jobID']]);
                continue;
            }
            $token=bin2hex(random_bytes(32));
            $wasExpiredLease=$row['status']==='Running';
            $update=$db->prepare(
                "UPDATE remediation_jobs
                 SET status='Running',leaseToken=:token,workerID=:worker,
                     leasedUntil=DATE_ADD(CURRENT_TIMESTAMP,INTERVAL {$leaseSeconds} SECOND),
                     lastHeartbeatAt=CURRENT_TIMESTAMP,attemptCount=attemptCount+1,
                     startedAt=COALESCE(startedAt,CURRENT_TIMESTAMP),nextAttemptAt=NULL,lastError=NULL,lastFailureClass=NULL
                 WHERE jobID=:id"
            );
            $update->execute([':token'=>$token,':worker'=>$workerID,':id'=>$row['jobID']]);
            $db->prepare("UPDATE exposure_matches SET status='Remediating' WHERE exposureID=:id")
                ->execute([':id'=>$row['exposureID']]);
            if (in_array($row['lifecycleStatus'],['Discovered','Triaged'],true)) {
                $db->prepare("UPDATE asset_vulnerabilities SET status='Confirmed' WHERE assetVulnID=:id")
                    ->execute([':id'=>$row['assetVulnID']]);
            }
            $db->prepare("UPDATE asset_vulnerabilities SET status='Remediation_In_Progress' WHERE assetVulnID=:id AND status='Confirmed'")
                ->execute([':id'=>$row['assetVulnID']]);
            $row['leaseToken']=$token;
            $row['workerID']=$workerID;
            $row['attemptCount']=(int)$row['attemptCount']+1;
            $row['reclaimedExpiredLease']=$wasExpiredLease;
            $row['effectiveMaxAttempts']=min((int)$row['maxAttempts'],(int)$row['maxPatchAttempts']);
            $db->commit();
            return $row;
        }
        $db->commit();
        return null;
    } catch (Throwable $e) {
        if ($db->inTransaction()) $db->rollBack();
        throw $e;
    }
}

function heartbeatRemediationLease(PDO $db, int $jobID, string $token, ?int $leaseSeconds = null): void
{
    $leaseSeconds ??= remediationLeaseSeconds();
    $leaseSeconds=max(60,min(1800,$leaseSeconds));
    $stmt=$db->prepare(
        "UPDATE remediation_jobs SET lastHeartbeatAt=CURRENT_TIMESTAMP,
         leasedUntil=DATE_ADD(CURRENT_TIMESTAMP,INTERVAL {$leaseSeconds} SECOND)
         WHERE jobID=:id AND status='Running' AND leaseToken=:token"
    );
    $stmt->execute([':id'=>$jobID,':token'=>$token]);
    if ($stmt->rowCount()!==1) throw new RuntimeException('Remediation lease lost; fenced worker must stop.');
}

function fencedJobUpdate(PDO $db, int $jobID, string $token, string $sqlSet, array $params = []): void
{
    $stmt=$db->prepare("UPDATE remediation_jobs SET {$sqlSet} WHERE jobID=:job AND status='Running' AND leaseToken=:lease");
    $stmt->execute($params + [':job'=>$jobID,':lease'=>$token]);
    if ($stmt->rowCount()!==1) throw new RuntimeException('Remediation lease lost before state update.');
}

function failOrRetryRemediationJob(PDO $db, array $job, string $message, string $failureClass, bool $retryable): array
{
    $attempt=(int)$job['attemptCount'];
    $max=max(1,(int)($job['effectiveMaxAttempts'] ?? $job['maxAttempts'] ?? 1));
    $retry=$retryable && $attempt < $max;
    $db->beginTransaction();
    try {
        if ($retry) {
            $delay=remediationRetryDelaySeconds($attempt);
            $status=($job['mode'] ?? '')==='Auto' ? 'Queued' : 'Approved';
            $stmt=$db->prepare(
                "UPDATE remediation_jobs
                 SET status=:status,leaseToken=NULL,workerID=NULL,leasedUntil=NULL,lastHeartbeatAt=NULL,
                     nextAttemptAt=DATE_ADD(CURRENT_TIMESTAMP,INTERVAL {$delay} SECOND),
                     lastError=:error,lastFailureClass=:class
                 WHERE jobID=:job AND status='Running' AND leaseToken=:lease"
            );
            $stmt->execute([':status'=>$status,':error'=>$message,':class'=>$failureClass,':job'=>$job['jobID'],':lease'=>$job['leaseToken']]);
            if ($stmt->rowCount()!==1) throw new RuntimeException('Remediation lease lost while scheduling retry.');
            $db->prepare("UPDATE exposure_matches SET status='Remediation_Queued' WHERE exposureID=:id")
                ->execute([':id'=>$job['exposureID']]);
            $db->prepare("UPDATE asset_vulnerabilities SET status='Confirmed' WHERE assetVulnID=:id AND status='Remediation_In_Progress'")
                ->execute([':id'=>$job['assetVulnID']]);
            $db->commit();
            return ['retry_scheduled'=>true,'delay_seconds'=>$delay,'attempt'=>$attempt,'max_attempts'=>$max];
        }
        $stmt=$db->prepare(
            "UPDATE remediation_jobs
             SET status='Failed',leaseToken=NULL,workerID=NULL,leasedUntil=NULL,lastHeartbeatAt=NULL,
                 completedAt=CURRENT_TIMESTAMP,lastError=:error,lastFailureClass=:class
             WHERE jobID=:job AND status='Running' AND leaseToken=:lease"
        );
        $stmt->execute([':error'=>$message,':class'=>$failureClass,':job'=>$job['jobID'],':lease'=>$job['leaseToken']]);
        if ($stmt->rowCount()!==1) throw new RuntimeException('Remediation lease lost while failing job.');
        $exposureStatus=$failureClass==='execution_outcome_unknown' ? 'Verification_Failed' : 'Confirmed';
        $db->prepare('UPDATE exposure_matches SET status=:status WHERE exposureID=:id')
            ->execute([':status'=>$exposureStatus,':id'=>$job['exposureID']]);
        $db->prepare("UPDATE asset_vulnerabilities SET status='Confirmed' WHERE assetVulnID=:id AND status='Remediation_In_Progress'")
            ->execute([':id'=>$job['assetVulnID']]);
        $db->commit();
        return ['retry_scheduled'=>false,'attempt'=>$attempt,'max_attempts'=>$max];
    } catch (Throwable $e) {
        if ($db->inTransaction()) $db->rollBack();
        throw $e;
    }
}
