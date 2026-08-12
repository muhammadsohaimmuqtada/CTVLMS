<?php
/** Continuous-cycle scheduling policy, telemetry, and overlap protection. */

const CTVLMS_CYCLE_LOCK_NAME = 'ctvlms:continuous-cycle:v1';

function schedulerWorkerID(): string
{
    $configured = trim((string)getenv('CTVLMS_CYCLE_WORKER_ID'));
    if ($configured !== '' && preg_match('/^[A-Za-z0-9._:@-]{1,160}$/', $configured)) return $configured;
    return substr((gethostname() ?: 'ctvlms') . ':' . getmypid(), 0, 160);
}

function tryAcquireCycleLock(PDO $db): bool
{
    $stmt = $db->prepare('SELECT GET_LOCK(:name, 0)');
    $stmt->execute([':name'=>CTVLMS_CYCLE_LOCK_NAME]);
    return (int)$stmt->fetchColumn() === 1;
}

function releaseCycleLock(PDO $db): void
{
    try {
        $stmt = $db->prepare('SELECT RELEASE_LOCK(:name)');
        $stmt->execute([':name'=>CTVLMS_CYCLE_LOCK_NAME]);
    } catch (Throwable) {
        // Connection close also releases MariaDB named locks. Do not mask the
        // cycle result if explicit cleanup itself fails.
    }
}

function createCycleRun(PDO $db, string $workerID, string $status = 'Running', ?string $summaryJson = null, ?string $error = null): int
{
    if (!in_array($status, ['Running','Succeeded','Partial','Failed','Skipped'], true)) {
        throw new InvalidArgumentException('Invalid continuous-cycle status.');
    }
    $stmt = $db->prepare(
        "INSERT INTO continuous_cycle_runs (workerID,status,completedAt,summaryJson,errorMessage)
         VALUES (:worker,:status,CASE WHEN :terminal=1 THEN CURRENT_TIMESTAMP ELSE NULL END,:summary,:error)"
    );
    $stmt->execute([
        ':worker'=>$workerID,
        ':status'=>$status,
        ':terminal'=>$status === 'Running' ? 0 : 1,
        ':summary'=>$summaryJson,
        ':error'=>$error,
    ]);
    return (int)$db->lastInsertId();
}

function finishCycleRun(PDO $db, int $cycleRunID, string $status, array $summary, ?string $error = null): void
{
    if (!in_array($status, ['Succeeded','Partial','Failed','Skipped'], true)) {
        throw new InvalidArgumentException('Invalid terminal continuous-cycle status.');
    }
    $json = json_encode($summary, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    $stmt = $db->prepare(
        "UPDATE continuous_cycle_runs
         SET status=:status,completedAt=CURRENT_TIMESTAMP,summaryJson=:summary,errorMessage=:error
         WHERE cycleRunID=:id"
    );
    $stmt->execute([
        ':status'=>$status, ':summary'=>$json, ':error'=>$error !== null ? substr($error, 0, 65535) : null,
        ':id'=>$cycleRunID,
    ]);
}

function boundedTimeoutFromEnv(string $envName, int $default, int $minimum, int $maximum): int
{
    $raw = trim((string)getenv($envName));
    $value = $raw === '' ? $default : (int)$raw;
    return max($minimum, min($maximum, $value));
}

function packageAdvisorySyncCadenceHours(): int
{
    $raw = trim((string)getenv('CTVLMS_PACKAGE_ADVISORY_SYNC_HOURS'));
    if ($raw === '') return 24;
    $hours = (int)$raw;
    if ($hours <= 0) return 0;
    return max(1, min(168, $hours));
}

function packageAdvisorySyncDue(PDO $db, int $cadenceHours, string $provider = 'DebianSecurityTracker'): array
{
    if ($cadenceHours <= 0) return ['due'=>false,'reason'=>'disabled','last_success'=>null];
    $stmt = $db->prepare(
        "SELECT completedAt
         FROM distribution_advisory_sync_runs
         WHERE provider=:provider AND status='Succeeded' AND completedAt IS NOT NULL
         ORDER BY completedAt DESC,syncRunID DESC LIMIT 1"
    );
    $stmt->execute([':provider'=>$provider]);
    $last = $stmt->fetchColumn();
    if ($last === false || $last === null || $last === '') {
        return ['due'=>true,'reason'=>'never_synchronized','last_success'=>null];
    }
    $lastTs = strtotime((string)$last);
    if ($lastTs === false) return ['due'=>true,'reason'=>'invalid_last_success','last_success'=>(string)$last];
    $due = $lastTs <= time() - ($cadenceHours * 3600);
    return [
        'due'=>$due,
        'reason'=>$due ? 'cadence_elapsed' : 'fresh',
        'last_success'=>(string)$last,
        'cadence_hours'=>$cadenceHours,
    ];
}

function cycleStageFailed(array $stage): bool
{
    return array_key_exists('ok', $stage) && $stage['ok'] === false;
}

function deriveCycleStatus(array $summary): string
{
    if (($summary['fatal_error'] ?? null) !== null) return 'Failed';
    if (isset($summary['nvd']) && cycleStageFailed($summary['nvd'])) return 'Partial';
    if (isset($summary['package_advisory_sync']) && cycleStageFailed($summary['package_advisory_sync'])) return 'Partial';
    foreach (['local_inventory','ssh_inventory','scans','patches'] as $group) {
        foreach (($summary[$group] ?? []) as $stage) if (cycleStageFailed($stage)) return 'Partial';
    }
    if (isset($summary['verification']) && cycleStageFailed($summary['verification'])) return 'Partial';
    return 'Succeeded';
}
