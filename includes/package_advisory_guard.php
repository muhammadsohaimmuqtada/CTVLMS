<?php
/** Advisory snapshot integrity guard for replacement-style provider syncs. */
require_once __DIR__ . '/package_advisories.php';

function advisorySnapshotGuardDecision(
    int $incomingRecords,
    ?int $previousRecords,
    int $absoluteMinimum = 1000,
    float $minimumRatio = 0.50,
    bool $allowShrink = false
): array {
    if ($incomingRecords < 0 || $absoluteMinimum < 0 || $minimumRatio < 0.0 || $minimumRatio > 1.0) {
        throw new InvalidArgumentException('Invalid advisory snapshot guard parameters.');
    }
    if ($allowShrink) {
        return ['allowed'=>true,'reason'=>'operator_override','incoming'=>$incomingRecords,'previous'=>$previousRecords];
    }
    if ($incomingRecords < $absoluteMinimum) {
        return ['allowed'=>false,'reason'=>'below_absolute_minimum','incoming'=>$incomingRecords,'previous'=>$previousRecords];
    }
    if ($previousRecords !== null && $previousRecords > 0) {
        $ratio = $incomingRecords / $previousRecords;
        if ($ratio < $minimumRatio) {
            return [
                'allowed'=>false,'reason'=>'unexpected_snapshot_shrink','incoming'=>$incomingRecords,
                'previous'=>$previousRecords,'ratio'=>$ratio,'minimum_ratio'=>$minimumRatio,
            ];
        }
        return [
            'allowed'=>true,'reason'=>'snapshot_size_acceptable','incoming'=>$incomingRecords,
            'previous'=>$previousRecords,'ratio'=>$ratio,'minimum_ratio'=>$minimumRatio,
        ];
    }
    return ['allowed'=>true,'reason'=>'first_snapshot_acceptable','incoming'=>$incomingRecords,'previous'=>null];
}

function countProviderAdvisoryRecords(DistributionAdvisoryProvider $provider, string $path): int
{
    $count = 0;
    foreach ($provider->recordsFromFile($path) as $_record) $count++;
    return $count;
}

function previousSuccessfulAdvisoryRecordCount(PDO $db, DistributionAdvisoryProvider $provider): ?int
{
    $stmt = $db->prepare(
        "SELECT recordsProcessed
         FROM distribution_advisory_sync_runs
         WHERE provider=:provider AND dataSourceIdentifier=:identifier AND status='Succeeded'
         ORDER BY syncRunID DESC LIMIT 1"
    );
    $stmt->execute([':provider'=>$provider->name(), ':identifier'=>$provider->dataSourceIdentifier()]);
    $value = $stmt->fetchColumn();
    return $value === false ? null : (int)$value;
}

function recordRejectedAdvisorySnapshot(
    PDO $db,
    DistributionAdvisoryProvider $provider,
    int $incomingRecords,
    array $decision
): int {
    $stmt = $db->prepare(
        "INSERT INTO distribution_advisory_sync_runs
            (provider,dataSourceIdentifier,sourceUrl,status,recordsProcessed,recordsStored,completedAt,errorMessage)
         VALUES (:provider,:identifier,:url,'Failed',:processed,0,CURRENT_TIMESTAMP,:error)"
    );
    $message = 'Snapshot guard rejected provider replacement: ' . ($decision['reason'] ?? 'unknown');
    if (isset($decision['previous'])) $message .= '; previous=' . (string)$decision['previous'];
    $message .= '; incoming=' . $incomingRecords;
    if (isset($decision['ratio'])) $message .= '; ratio=' . sprintf('%.4f', (float)$decision['ratio']);
    $stmt->execute([
        ':provider'=>$provider->name(), ':identifier'=>$provider->dataSourceIdentifier(),
        ':url'=>$provider->sourceUrl(), ':processed'=>$incomingRecords, ':error'=>$message,
    ]);
    return (int)$db->lastInsertId();
}

function ingestDistributionAdvisoriesGuarded(
    PDO $db,
    DistributionAdvisoryProvider $provider,
    string $path,
    bool $allowShrink = false
): array {
    $absoluteMinimum = max(0, (int)(getenv('CTVLMS_ADVISORY_MIN_RECORDS') ?: 1000));
    $minimumRatio = (float)(getenv('CTVLMS_ADVISORY_MIN_RATIO') ?: 0.50);
    $minimumRatio = max(0.0, min(1.0, $minimumRatio));

    $incoming = countProviderAdvisoryRecords($provider, $path);
    $previous = previousSuccessfulAdvisoryRecordCount($db, $provider);
    $decision = advisorySnapshotGuardDecision($incoming, $previous, $absoluteMinimum, $minimumRatio, $allowShrink);
    if (!$decision['allowed']) {
        $runID = recordRejectedAdvisorySnapshot($db, $provider, $incoming, $decision);
        throw new RuntimeException(
            'Advisory snapshot rejected by integrity guard (' . $decision['reason'] . "). Failed sync run #{$runID}. " .
            'Use --allow-shrink only after verifying the provider intentionally changed its dataset.'
        );
    }

    $result = ingestDistributionAdvisories($db, $provider, $path);
    $result['snapshot_guard'] = $decision;
    return $result;
}
