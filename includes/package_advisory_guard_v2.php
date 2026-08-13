<?php
/** Provider snapshot preflight guard against accidental feed collapse. */
require_once __DIR__ . '/package_advisories.php';

function countProviderRecords(DistributionAdvisoryProvider $provider, string $path): int
{
    $count = 0;
    foreach ($provider->recordsFromFile($path) as $_record) $count++;
    return $count;
}

function previousProviderRecordCount(PDO $db, DistributionAdvisoryProvider $provider): int
{
    $stmt = $db->prepare('SELECT COUNT(*) FROM distribution_advisories WHERE provider=:provider');
    $stmt->execute([':provider'=>$provider->name()]);
    return (int)$stmt->fetchColumn();
}

function assertAdvisorySnapshotIsSane(
    int $incoming,
    int $previous,
    bool $allowShrink = false,
    ?int $absoluteMinimum = null,
    ?float $minimumRatio = null
): void {
    if ($allowShrink || $previous === 0) return;

    $absoluteMinimum ??= max(1, (int)(getenv('CTVLMS_ADVISORY_MIN_RECORDS') ?: 1000));
    $minimumRatio ??= (float)(getenv('CTVLMS_ADVISORY_MIN_RATIO') ?: 0.60);
    $minimumRatio = max(0.05, min(1.0, $minimumRatio));

    if ($incoming < $absoluteMinimum) {
        throw new RuntimeException("Advisory snapshot rejected: {$incoming} records is below minimum {$absoluteMinimum}.");
    }
    $ratio = $previous > 0 ? $incoming / $previous : 1.0;
    if ($ratio < $minimumRatio) {
        throw new RuntimeException(sprintf(
            'Advisory snapshot rejected: %d records is %.2f%% of previous %d (minimum %.2f%%).',
            $incoming,
            $ratio * 100,
            $previous,
            $minimumRatio * 100
        ));
    }
}

function ingestDistributionAdvisoriesGuarded(
    PDO $db,
    DistributionAdvisoryProvider $provider,
    string $path,
    bool $allowShrink = false
): array {
    $incoming = countProviderRecords($provider, $path);
    $previous = previousProviderRecordCount($db, $provider);
    $override = $allowShrink || getenv('CTVLMS_ALLOW_ADVISORY_SHRINK') === '1';
    assertAdvisorySnapshotIsSane($incoming, $previous, $override);
    $result = ingestDistributionAdvisories($db, $provider, $path);
    $result['preflight_records'] = $incoming;
    $result['previous_records'] = $previous;
    $result['shrink_override'] = $override;
    return $result;
}
