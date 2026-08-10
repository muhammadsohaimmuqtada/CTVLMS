<?php
/**
 * Managed endpoint inventory collection.
 *
 * Network discovery is intentionally kept separate from authoritative endpoint
 * facts. This module records OS/platform facts and package inventory gathered
 * locally (and can be reused by future SSH/agent collectors).
 */

function parseOsReleaseText(string $text): array
{
    $facts = [];
    foreach (preg_split('/\R/', $text) ?: [] as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) continue;
        [$key, $value] = explode('=', $line, 2);
        $key = trim($key);
        $value = trim($value);
        if ($value !== '' && (($value[0] === '"' && str_ends_with($value, '"')) || ($value[0] === "'" && str_ends_with($value, "'")))) {
            $value = substr($value, 1, -1);
        }
        $facts[$key] = stripcslashes($value);
    }
    return $facts;
}

function localHostFacts(): array
{
    $osRelease = is_readable('/etc/os-release') ? parseOsReleaseText((string)file_get_contents('/etc/os-release')) : [];
    $family = strtolower(PHP_OS_FAMILY);
    return [
        'hostname' => gethostname() ?: php_uname('n'),
        'os_family' => $family,
        'os_id' => strtolower((string)($osRelease['ID'] ?? $family)),
        'os_name' => (string)($osRelease['PRETTY_NAME'] ?? PHP_OS),
        'os_version' => (string)($osRelease['VERSION_ID'] ?? ''),
        'architecture' => php_uname('m'),
        'kernel' => php_uname('r'),
        'package_manager' => is_executable('/usr/bin/dpkg-query') ? 'apt' : 'none',
    ];
}

function platformCpesForFacts(array $facts): array
{
    return match (strtolower((string)($facts['os_family'] ?? ''))) {
        'linux' => ['cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*'],
        'windows' => ['cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*'],
        'darwin' => ['cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*'],
        default => [],
    };
}

function parseDpkgInventory(string $text): array
{
    $packages = [];
    foreach (preg_split('/\R/', $text) ?: [] as $line) {
        if ($line === '') continue;
        $parts = explode("\t", $line);
        if (count($parts) < 3) continue;
        [$package, $version, $arch] = array_map('trim', array_slice($parts, 0, 3));
        if ($package === '' || $version === '') continue;
        $packages[] = ['package' => $package, 'version' => $version, 'architecture' => $arch];
    }
    return $packages;
}

function runCommand(array $command): array
{
    $descriptor = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($command, $descriptor, $pipes);
    if (!is_resource($proc)) throw new RuntimeException('Unable to start inventory command.');
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    $exit = proc_close($proc);
    return ['exit' => $exit, 'stdout' => $stdout, 'stderr' => $stderr];
}

function collectDpkgPackages(): array
{
    if (!is_executable('/usr/bin/dpkg-query')) return [];
    $result = runCommand(['/usr/bin/dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Architecture}\n']);
    if ($result['exit'] !== 0) throw new RuntimeException('dpkg-query failed: ' . trim($result['stderr']));
    return parseDpkgInventory($result['stdout']);
}

function upsertAssetFact(PDO $db, int $assetID, string $key, string $value, string $source = 'Local', float $confidence = 1.0): void
{
    $stmt = $db->prepare(
        'INSERT INTO asset_facts (assetID, factKey, factValue, source, confidence)
         VALUES (:asset, :key, :value, :source, :confidence)
         ON DUPLICATE KEY UPDATE factValue = VALUES(factValue), confidence = VALUES(confidence), lastSeen = CURRENT_TIMESTAMP'
    );
    $stmt->execute([':asset'=>$assetID, ':key'=>$key, ':value'=>$value, ':source'=>$source, ':confidence'=>$confidence]);
}

function collectLocalInventory(PDO $db, int $assetID): array
{
    $asset = $db->prepare('SELECT assetID FROM assets WHERE assetID = :id');
    $asset->execute([':id' => $assetID]);
    if (!$asset->fetchColumn()) throw new RuntimeException('Unknown asset ID.');

    $facts = localHostFacts();
    $db->beginTransaction();
    try {
        foreach ($facts as $key => $value) upsertAssetFact($db, $assetID, $key, (string)$value, 'Local', 1.0);
        $updateAsset = $db->prepare('UPDATE assets SET osPlatform = :platform WHERE assetID = :id');
        $updateAsset->execute([':platform' => $facts['os_name'], ':id' => $assetID]);

        $db->prepare("UPDATE asset_platform_cpes SET isActive = 0 WHERE assetID = :asset AND source = 'Local'")
            ->execute([':asset' => $assetID]);
        $platform = $db->prepare(
            "INSERT INTO asset_platform_cpes (assetID, cpe, source, isActive)
             VALUES (:asset, :cpe, 'Local', 1)
             ON DUPLICATE KEY UPDATE isActive = 1, lastSeen = CURRENT_TIMESTAMP"
        );
        foreach (platformCpesForFacts($facts) as $cpe) $platform->execute([':asset'=>$assetID, ':cpe'=>$cpe]);

        $packages = collectDpkgPackages();
        if ($packages) {
            $db->prepare("UPDATE asset_software SET isActive = 0 WHERE assetID = :asset AND source = 'Agent'")
                ->execute([':asset' => $assetID]);
            $insert = $db->prepare(
                "INSERT INTO asset_software
                    (assetID, vendor, product, version, cpe, packageManager, packageName, source, isActive)
                 VALUES (:asset, NULL, :product, :version, NULL, 'apt', :package, 'Agent', 1)
                 ON DUPLICATE KEY UPDATE isActive = 1, lastSeen = CURRENT_TIMESTAMP"
            );
            foreach ($packages as $package) {
                $insert->execute([
                    ':asset'=>$assetID, ':product'=>$package['package'], ':version'=>$package['version'], ':package'=>$package['package'],
                ]);
            }
        }
        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) $db->rollBack();
        throw $e;
    }

    return ['asset_id'=>$assetID, 'facts'=>$facts, 'platform_cpes'=>platformCpesForFacts($facts), 'packages'=>count($packages ?? [])];
}
