<?php
/**
 * CTVLMS — NVD CVE ingestion.
 *
 * Supports incremental last-modified synchronization, targeted CVE refresh,
 * and bounded backfill for pre-v3 databases whose full NVD configuration trees
 * have not yet been populated.
 */

function nvdHttpGet(string $url): ?array
{
    $headers = ['User-Agent: CTVLMS/3.1', 'Accept: application/json'];
    $apiKey = trim((string)getenv('NVD_API_KEY'));
    if ($apiKey !== '') $headers[] = 'apiKey: ' . $apiKey;
    $options = ['http' => [
        'method' => 'GET',
        'header' => implode("\r\n", $headers) . "\r\n",
        'timeout' => 30,
        'ignore_errors' => true,
    ]];
    $delay = 2;
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $context = stream_context_create($options);
        $body = @file_get_contents($url, false, $context);
        $status = $http_response_header[0] ?? '';
        if ($body !== false && str_contains($status, '200')) {
            $decoded = json_decode($body, true);
            return is_array($decoded) ? $decoded : null;
        }
        $retryable = str_contains($status, '403') || str_contains($status, '429') || str_contains($status, '500') ||
            str_contains($status, '502') || str_contains($status, '503') || str_contains($status, '504');
        if (!$retryable || $attempt === 4) break;
        sleep($delay);
        $delay = min(16, $delay * 2);
    }
    return null;
}

function nvdEnglishDescription(array $cve): string
{
    foreach (($cve['descriptions'] ?? []) as $description) {
        if (($description['lang'] ?? '') === 'en') return trim((string)($description['value'] ?? '')) ?: 'No description available';
    }
    return 'No description available';
}

function nvdCvss(array $cve): array
{
    foreach (['cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2'] as $path) {
        $metric = $cve['metrics'][$path][0]['cvssData'] ?? null;
        if (!is_array($metric) || !isset($metric['baseScore'])) continue;
        $score = (float)$metric['baseScore'];
        $severity = strtoupper((string)($metric['baseSeverity'] ?? ''));
        if (!in_array($severity, ['LOW','MEDIUM','HIGH','CRITICAL'], true)) {
            $severity = $score >= 9.0 ? 'CRITICAL' : ($score >= 7.0 ? 'HIGH' : ($score >= 4.0 ? 'MEDIUM' : 'LOW'));
        }
        return [$score, ucfirst(strtolower($severity))];
    }
    return [null, 'Low'];
}

function collectNvdCpeMatches(array $node, array &$out, bool $complex = false): void
{
    $operator = strtoupper((string)($node['operator'] ?? 'OR'));
    $nodeComplex = $complex || $operator === 'AND' || !empty($node['negate']);
    foreach (($node['cpeMatch'] ?? []) as $match) {
        if (!is_array($match) || empty($match['criteria'])) continue;
        $out[] = [
            'criteria' => (string)$match['criteria'],
            'matchCriteriaId' => isset($match['matchCriteriaId']) ? (string)$match['matchCriteriaId'] : null,
            'vulnerable' => !empty($match['vulnerable']) ? 1 : 0,
            'configurationComplex' => $nodeComplex ? 1 : 0,
            'versionStartIncluding' => $match['versionStartIncluding'] ?? null,
            'versionStartExcluding' => $match['versionStartExcluding'] ?? null,
            'versionEndIncluding' => $match['versionEndIncluding'] ?? null,
            'versionEndExcluding' => $match['versionEndExcluding'] ?? null,
        ];
    }
    foreach (($node['nodes'] ?? []) as $child) if (is_array($child)) collectNvdCpeMatches($child, $out, $nodeComplex);
}

function extractNvdCpeMatches(array $cve): array
{
    $matches = [];
    foreach (($cve['configurations'] ?? []) as $configuration) if (is_array($configuration)) collectNvdCpeMatches($configuration, $matches, false);
    return $matches;
}

function normalizeNvdCveIds(array $ids): array
{
    $out = [];
    foreach ($ids as $id) {
        $id = strtoupper(trim((string)$id));
        if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $id)) throw new InvalidArgumentException('Invalid CVE identifier: ' . $id);
        $out[$id] = true;
    }
    return array_keys($out);
}

function nvdPrepareStatements(PDO $db): array
{
    return [
        'upsertVuln' => $db->prepare(
            'INSERT INTO vulnerabilities (cveID, title, description, cvssScore, severity, cwe, publishedDate)
             VALUES (:cveID, :title, :description, :cvssScore, :severity, :cwe, :publishedDate)
             ON DUPLICATE KEY UPDATE title=VALUES(title), description=VALUES(description), cvssScore=VALUES(cvssScore), severity=VALUES(severity), cwe=VALUES(cwe), publishedDate=VALUES(publishedDate)'
        ),
        'findVuln' => $db->prepare('SELECT vulnID FROM vulnerabilities WHERE cveID = :cveID LIMIT 1'),
        'clearCpes' => $db->prepare("DELETE FROM vulnerability_cpe_matches WHERE vulnID = :vulnID AND source = 'NVD'"),
        'clearConfigs' => $db->prepare("DELETE FROM vulnerability_configurations WHERE vulnID = :vulnID AND source = 'NVD'"),
        'insertCpe' => $db->prepare(
            "INSERT INTO vulnerability_cpe_matches
                (vulnID, criteria, matchCriteriaId, vulnerable, configurationComplex,
                 versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding, source)
             VALUES (:vulnID, :criteria, :matchCriteriaId, :vulnerable, :complex, :vsi, :vse, :vei, :vee, 'NVD')"
        ),
        'insertConfig' => $db->prepare(
            "INSERT INTO vulnerability_configurations (vulnID, configIndex, configurationJson, source)
             VALUES (:vulnID, :configIndex, :configurationJson, 'NVD')"
        ),
        'markSync' => $db->prepare(
            "UPDATE vulnerabilities SET nvdLastSyncedAt=CURRENT_TIMESTAMP, nvdConfigurationState=:state WHERE vulnID=:vulnID"
        ),
    ];
}

function persistNvdCve(PDO $db, array $cve, array $statements): bool
{
    if (empty($cve['id'])) return false;
    $cveID = strtoupper((string)$cve['id']);
    if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cveID)) return false;
    $description = nvdEnglishDescription($cve);
    $title = strlen($description) > 160 ? substr($description, 0, 157) . '...' : $description;
    [$score, $severity] = nvdCvss($cve);
    $cwe = null;
    foreach (($cve['weaknesses'] ?? []) as $weakness) {
        foreach (($weakness['description'] ?? []) as $desc) {
            $value = (string)($desc['value'] ?? '');
            if (preg_match('/^CWE-\d+$/', $value)) { $cwe = $value; break 2; }
        }
    }
    $published = !empty($cve['published']) ? date('Y-m-d', strtotime($cve['published'])) : null;
    $configurations = array_values(array_filter($cve['configurations'] ?? [], 'is_array'));
    $db->beginTransaction();
    try {
        $statements['upsertVuln']->execute([
            ':cveID'=>$cveID, ':title'=>$title, ':description'=>$description,
            ':cvssScore'=>$score, ':severity'=>$severity, ':cwe'=>$cwe, ':publishedDate'=>$published,
        ]);
        $statements['findVuln']->execute([':cveID'=>$cveID]);
        $vulnID = (int)$statements['findVuln']->fetchColumn();
        if ($vulnID <= 0) throw new RuntimeException('Unable to resolve imported CVE: ' . $cveID);
        $statements['clearCpes']->execute([':vulnID'=>$vulnID]);
        $statements['clearConfigs']->execute([':vulnID'=>$vulnID]);
        foreach ($configurations as $index => $configuration) {
            $json = json_encode($configuration, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $statements['insertConfig']->execute([':vulnID'=>$vulnID, ':configIndex'=>(int)$index, ':configurationJson'=>$json]);
        }
        foreach (extractNvdCpeMatches($cve) as $match) {
            $statements['insertCpe']->execute([
                ':vulnID'=>$vulnID, ':criteria'=>$match['criteria'], ':matchCriteriaId'=>$match['matchCriteriaId'],
                ':vulnerable'=>$match['vulnerable'], ':complex'=>$match['configurationComplex'],
                ':vsi'=>$match['versionStartIncluding'], ':vse'=>$match['versionStartExcluding'],
                ':vei'=>$match['versionEndIncluding'], ':vee'=>$match['versionEndExcluding'],
            ]);
        }
        $statements['markSync']->execute([':vulnID'=>$vulnID, ':state'=>$configurations ? 'Present' : 'None']);
        $db->commit();
        return true;
    } catch (Throwable $ex) {
        if ($db->inTransaction()) $db->rollBack();
        throw $ex;
    }
}

function persistNvdPage(PDO $db, array $page, array $statements): int
{
    $processed = 0;
    foreach (($page['vulnerabilities'] ?? []) as $item) {
        $cve = $item['cve'] ?? null;
        if (is_array($cve) && persistNvdCve($db, $cve, $statements)) $processed++;
    }
    return $processed;
}

function syncNistCVEs(PDO $db): int|false
{
    $hours = max(1, min(168, (int)(getenv('NVD_SYNC_HOURS') ?: 6)));
    $end = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    $start = $end->modify('-' . $hours . ' hours');
    $baseParams = [
        'lastModStartDate' => $start->format('Y-m-d\TH:i:s.000P'),
        'lastModEndDate' => $end->format('Y-m-d\TH:i:s.000P'),
        'resultsPerPage' => 200,
    ];
    $statements = nvdPrepareStatements($db);
    $processed = 0; $startIndex = 0; $total = null;
    do {
        $params = $baseParams; $params['startIndex'] = $startIndex;
        $url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
        $page = nvdHttpGet($url);
        if ($page === null || !isset($page['vulnerabilities'])) return $processed > 0 ? $processed : false;
        $total = (int)($page['totalResults'] ?? count($page['vulnerabilities']));
        $processed += persistNvdPage($db, $page, $statements);
        $received = count($page['vulnerabilities']);
        $startIndex += $received;
        if ($received === 0) break;
    } while ($startIndex < $total);
    logAction('SYNC', 'vulnerabilities', null, "NVD incremental sync processed {$processed} recently modified CVEs");
    return $processed;
}

function syncNistCveIds(PDO $db, array $ids): int|false
{
    $ids = normalizeNvdCveIds($ids);
    if (!$ids) return 0;
    $statements = nvdPrepareStatements($db);
    $processed = 0;
    $batches = array_chunk($ids, 100);
    $delay = max(0, min(30, (int)(getenv('NVD_REQUEST_DELAY_SECONDS') ?: 6)));
    foreach ($batches as $index => $batch) {
        $url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?' . http_build_query(['cveIds'=>implode(',', $batch)], '', '&', PHP_QUERY_RFC3986);
        $page = nvdHttpGet($url);
        if ($page === null || !isset($page['vulnerabilities'])) return $processed > 0 ? $processed : false;
        $processed += persistNvdPage($db, $page, $statements);
        if ($delay > 0 && $index < count($batches) - 1) sleep($delay);
    }
    logAction('SYNC', 'vulnerabilities', null, "NVD targeted sync processed {$processed} CVEs");
    return $processed;
}

function backfillUnknownNvdConfigurations(PDO $db, int $limit = 100): array
{
    $limit = max(1, min(1000, $limit));
    $ids = $db->query(
        "SELECT cveID FROM vulnerabilities
         WHERE nvdConfigurationState='Unknown'
           AND cveID REGEXP '^CVE-[0-9]{4}-[0-9]{4,}$'
         ORDER BY publishedDate DESC, vulnID DESC LIMIT {$limit}"
    )->fetchAll(PDO::FETCH_COLUMN);
    if (!$ids) return ['requested'=>0, 'processed'=>0, 'remaining_unknown'=>0, 'ok'=>true];
    $processed = syncNistCveIds($db, $ids);
    $remaining = (int)$db->query("SELECT COUNT(*) FROM vulnerabilities WHERE nvdConfigurationState='Unknown'")->fetchColumn();
    return [
        'requested'=>count($ids),
        'processed'=>$processed === false ? 0 : $processed,
        'remaining_unknown'=>$remaining,
        'ok'=>$processed !== false,
    ];
}

if (php_sapi_name() === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    require_once __DIR__ . '/../config/config.php';
    require_once __DIR__ . '/../config/database.php';
    require_once __DIR__ . '/audit.php';
    $db = getDB();
    $mode = (string)($argv[1] ?? '');
    if ($mode === '--cve') {
        try { $ids = normalizeNvdCveIds(array_slice($argv, 2)); }
        catch (InvalidArgumentException $e) { fwrite(STDERR, $e->getMessage() . "\n"); exit(2); }
        if (!$ids) { fwrite(STDERR, "Usage: php includes/sync_cve.php --cve CVE-YYYY-NNNN [CVE-...]\n"); exit(2); }
        $count = syncNistCveIds($db, $ids);
        if ($count === false) { fwrite(STDERR, "Targeted NVD synchronization failed.\n"); exit(1); }
        echo "NVD targeted synchronization processed {$count} CVEs.\n";
        exit(0);
    }
    if ($mode === '--backfill-missing') {
        $limit = isset($argv[2]) ? (int)$argv[2] : 100;
        $result = backfillUnknownNvdConfigurations($db, $limit);
        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
        exit($result['ok'] ? 0 : 1);
    }
    if ($mode !== '') {
        fwrite(STDERR, "Usage: php includes/sync_cve.php [--cve CVE-... ... | --backfill-missing [limit]]\n");
        exit(2);
    }
    $count = syncNistCVEs($db);
    if ($count === false) { fwrite(STDERR, "NVD synchronization failed.\n"); exit(1); }
    echo "NVD synchronization processed {$count} CVEs.\n";
}
