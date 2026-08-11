<?php
/** Distribution package advisory providers and transactional ingestion. */

interface DistributionAdvisoryProvider
{
    public function name(): string;
    public function dataSourceIdentifier(): string;
    public function sourceUrl(): string;
    public function recordsFromFile(string $path): Generator;
}

final class DebianSecurityTrackerProvider implements DistributionAdvisoryProvider
{
    private const URL = 'https://security-tracker.debian.org/tracker/data/json';

    public function name(): string { return 'DebianSecurityTracker'; }
    public function dataSourceIdentifier(): string { return 'debian-security-tracker-json-v1'; }
    public function sourceUrl(): string { return self::URL; }

    public static function normalizeReleaseState(array $release): string
    {
        $status = strtolower(trim((string)($release['status'] ?? '')));
        $fixed = trim((string)($release['fixed_version'] ?? ''));
        if ($status === 'open') return 'Vulnerable';
        if ($status === 'undetermined') return 'Unknown';
        if ($status === 'resolved' && $fixed === '0') return 'Not_Affected';
        if ($status === 'resolved' && $fixed !== '') return 'Fixed';
        return 'Unknown';
    }

    public function recordsFromFile(string $path): Generator
    {
        foreach (streamTopLevelJsonObject($path) as [$sourcePackage, $cves]) {
            if (!is_array($cves) || !preg_match('/^[a-z0-9][a-z0-9+.-]*$/i', $sourcePackage)) continue;
            foreach ($cves as $cve => $entry) {
                if (!is_array($entry) || !preg_match('/^CVE-\d{4}-\d{4,}$/', (string)$cve)) continue;
                foreach (($entry['releases'] ?? []) as $suite => $release) {
                    if (!is_array($release) || !is_string($suite) || $suite === '') continue;
                    $state = self::normalizeReleaseState($release);
                    $fixed = trim((string)($release['fixed_version'] ?? ''));
                    yield [
                        'advisory_identifier'=>(string)$cve,
                        'cve_id'=>(string)$cve,
                        'description'=>(string)($entry['description'] ?? ''),
                        'distribution'=>'debian',
                        'suite'=>strtolower($suite),
                        'source_package'=>strtolower($sourcePackage),
                        'state'=>$state,
                        'fixed_version'=>($fixed === '' || $fixed === '0') ? null : $fixed,
                        'urgency'=>isset($release['urgency']) ? (string)$release['urgency'] : null,
                        'severity'=>null,
                        'upstream_reference'=>'https://security-tracker.debian.org/tracker/' . rawurlencode((string)$cve),
                        'provider_record_json'=>json_encode($release, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
                    ];
                }
            }
        }
    }
}

/**
 * Stream a top-level JSON object as [key, decodedValue] pairs. This keeps the
 * large Debian feed bounded to one source-package object in memory.
 */
function streamTopLevelJsonObject(string $path): Generator
{
    $handle = fopen($path, 'rb');
    if ($handle === false) throw new RuntimeException('Unable to open advisory JSON.');
    try {
        do { $char = fgetc($handle); } while ($char !== false && ctype_space($char));
        if ($char !== '{') throw new RuntimeException('Advisory feed is not a JSON object.');
        while (true) {
            do { $char = fgetc($handle); } while ($char !== false && (ctype_space($char) || $char === ','));
            if ($char === '}') break;
            if ($char !== '"') throw new RuntimeException('Malformed advisory JSON key.');
            $encodedKey = '"'; $escaped = false;
            while (($char = fgetc($handle)) !== false) {
                $encodedKey .= $char;
                if ($char === '"' && !$escaped) break;
                $escaped = $char === '\\' && !$escaped;
                if ($char !== '\\') $escaped = false;
            }
            $key = json_decode($encodedKey, true, 2, JSON_THROW_ON_ERROR);
            do { $char = fgetc($handle); } while ($char !== false && ctype_space($char));
            if ($char !== ':') throw new RuntimeException('Malformed advisory JSON separator.');
            do { $char = fgetc($handle); } while ($char !== false && ctype_space($char));
            if ($char !== '{') throw new RuntimeException('Malformed advisory JSON value.');
            $json = '{'; $depth = 1; $inString = false; $escaped = false;
            while ($depth > 0 && ($char = fgetc($handle)) !== false) {
                $json .= $char;
                if ($inString) {
                    if ($char === '"' && !$escaped) $inString = false;
                    $escaped = $char === '\\' && !$escaped;
                    if ($char !== '\\') $escaped = false;
                    continue;
                }
                if ($char === '"') { $inString = true; $escaped = false; continue; }
                if ($char === '{') $depth++;
                elseif ($char === '}') $depth--;
            }
            if ($depth !== 0) throw new RuntimeException('Truncated advisory JSON value.');
            yield [(string)$key, json_decode($json, true, 512, JSON_THROW_ON_ERROR)];
        }
    } finally {
        fclose($handle);
    }
}

function downloadAdvisoryFeed(string $url, int $timeoutSeconds = 180, int $retries = 3, int $maxBytes = 268435456): string
{
    if (!str_starts_with($url, 'https://')) throw new RuntimeException('Advisory feeds require HTTPS.');
    $lastError = 'download failed';
    for ($attempt = 1; $attempt <= $retries; $attempt++) {
        $path = tempnam(sys_get_temp_dir(), 'ctvlms-advisory-');
        if ($path === false) throw new RuntimeException('Unable to allocate advisory download file.');
        $context = stream_context_create(['http'=>[
            'timeout'=>$timeoutSeconds, 'follow_location'=>0,
            'header'=>"Accept: application/json\r\nUser-Agent: CTVLMS-package-intelligence/1.0\r\n",
        ]]);
        $input = @fopen($url, 'rb', false, $context);
        if ($input !== false) {
            $output = fopen($path, 'wb');
            $bytes = 0; $ok = $output !== false;
            while ($ok && !feof($input)) {
                $chunk = fread($input, 1048576);
                if ($chunk === false) { $ok = false; break; }
                $bytes += strlen($chunk);
                if ($bytes > $maxBytes || fwrite($output, $chunk) !== strlen($chunk)) { $ok = false; break; }
            }
            fclose($input); if ($output !== false) fclose($output);
            if ($ok && $bytes > 2) return $path;
            $lastError = $bytes > $maxBytes ? 'advisory feed exceeds size limit' : 'incomplete advisory response';
        } else {
            $lastError = 'unable to connect to advisory provider';
        }
        @unlink($path);
        if ($attempt < $retries) usleep(250000 * $attempt);
    }
    throw new RuntimeException($lastError);
}

function severityFromDebianUrgency(?string $urgency): string
{
    return match (strtolower(trim((string)$urgency))) {
        'high' => 'High',
        'medium' => 'Medium',
        'low', 'unimportant' => 'Low',
        default => 'Medium',
    };
}

function ingestDistributionAdvisories(PDO $db, DistributionAdvisoryProvider $provider, string $path): array
{
    $run = $db->prepare('INSERT INTO distribution_advisory_sync_runs (provider,dataSourceIdentifier,sourceUrl) VALUES (:provider,:identifier,:url)');
    $run->execute([':provider'=>$provider->name(), ':identifier'=>$provider->dataSourceIdentifier(), ':url'=>$provider->sourceUrl()]);
    $runID = (int)$db->lastInsertId(); $processed = $stored = 0;
    try {
        $db->beginTransaction();
        $vulnerability = $db->prepare(
            "INSERT INTO vulnerabilities (cveID,title,description,cvssScore,severity,publishedDate)
             VALUES (:cve,:title,:description,NULL,:severity,NULL)
             ON DUPLICATE KEY UPDATE description=CASE WHEN description IS NULL OR description='' THEN VALUES(description) ELSE description END"
        );
        $advisory = $db->prepare(
            "INSERT INTO distribution_advisories
                (recordKey,advisoryIdentifier,cveID,distribution,suite,sourcePackage,state,fixedVersion,
                 urgency,severity,upstreamReference,sourceUrl,dataSourceIdentifier,provider,lastSyncRunID,providerRecordJson)
             VALUES (:key,:advisory,:cve,:distribution,:suite,:source,:state,:fixed,:urgency,:severity,
                     :reference,:url,:identifier,:provider,:run,:json)
             ON DUPLICATE KEY UPDATE state=VALUES(state),fixedVersion=VALUES(fixedVersion),urgency=VALUES(urgency),
                 severity=VALUES(severity),upstreamReference=VALUES(upstreamReference),sourceUrl=VALUES(sourceUrl),
                 dataSourceIdentifier=VALUES(dataSourceIdentifier),lastSyncRunID=VALUES(lastSyncRunID),
                 providerRecordJson=VALUES(providerRecordJson),
                 lastSyncedAt=CURRENT_TIMESTAMP"
        );
        foreach ($provider->recordsFromFile($path) as $record) {
            $processed++;
            $urgency = $record['urgency'] ?? null;
            $severity = $record['severity'] ?? severityFromDebianUrgency($urgency);
            $vulnerability->execute([
                ':cve'=>$record['cve_id'], ':title'=>$record['cve_id'] . ' package advisory',
                ':description'=>$record['description'], ':severity'=>$severity,
            ]);
            $key = hash('sha256', implode('|', [
                $provider->name(), $record['distribution'], $record['suite'],
                $record['source_package'], $record['cve_id'],
            ]));
            $advisory->execute([
                ':key'=>$key, ':advisory'=>$record['advisory_identifier'], ':cve'=>$record['cve_id'],
                ':distribution'=>$record['distribution'], ':suite'=>$record['suite'], ':source'=>$record['source_package'],
                ':state'=>$record['state'], ':fixed'=>$record['fixed_version'], ':urgency'=>$urgency,
                ':severity'=>$record['severity'] ?? null, ':reference'=>$record['upstream_reference'],
                ':url'=>$provider->sourceUrl(), ':identifier'=>$provider->dataSourceIdentifier(),
                ':provider'=>$provider->name(), ':run'=>$runID, ':json'=>$record['provider_record_json'],
            ]);
            $stored += $advisory->rowCount() > 0 ? 1 : 0;
        }
        $removeStale = $db->prepare('DELETE FROM distribution_advisories WHERE provider=:provider AND COALESCE(lastSyncRunID,0)<>:run');
        $removeStale->execute([':provider'=>$provider->name(), ':run'=>$runID]);
        $db->commit();
        $done = $db->prepare("UPDATE distribution_advisory_sync_runs SET status='Succeeded',recordsProcessed=:processed,recordsStored=:stored,completedAt=CURRENT_TIMESTAMP WHERE syncRunID=:id");
        $done->execute([':processed'=>$processed, ':stored'=>$stored, ':id'=>$runID]);
        return ['provider'=>$provider->name(), 'processed'=>$processed, 'stored'=>$stored, 'sync_run_id'=>$runID];
    } catch (Throwable $error) {
        if ($db->inTransaction()) $db->rollBack();
        $failed = $db->prepare("UPDATE distribution_advisory_sync_runs SET status='Failed',recordsProcessed=:processed,errorMessage=:error,completedAt=CURRENT_TIMESTAMP WHERE syncRunID=:id");
        $failed->execute([':processed'=>$processed, ':error'=>substr($error->getMessage(), 0, 65535), ':id'=>$runID]);
        throw $error;
    }
}
