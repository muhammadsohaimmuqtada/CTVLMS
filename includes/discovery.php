<?php
/**
 * CTVLMS — Network discovery ingestion.
 *
 * Imports Nmap XML into managed asset/service inventory and explicitly retires
 * services that disappear from a later successful scan of the same host.
 */

function importNmapXml(PDO $db, string $xml, string $target = 'manual-import'): array
{
    libxml_use_internal_errors(true);
    $doc = simplexml_load_string($xml);
    if ($doc === false) {
        $errors = array_map(static fn($e) => trim($e->message), libxml_get_errors());
        libxml_clear_errors();
        throw new RuntimeException('Invalid Nmap XML: ' . implode('; ', $errors));
    }

    $run = $db->prepare("INSERT INTO scan_runs (target, scanner, status) VALUES (:target, 'nmap', 'Running')");
    $run->execute([':target' => $target]);
    $scanRunID = (int)$db->lastInsertId();
    $hostCount = $serviceCount = $retiredServiceCount = 0;

    try {
        foreach ($doc->host as $host) {
            if ((string)($host->status['state'] ?? '') !== 'up') continue;

            $ip = null;
            foreach ($host->address as $address) {
                $addrType = (string)$address['addrtype'];
                if ($addrType === 'ipv4' || ($ip === null && $addrType === 'ipv6')) {
                    $ip = (string)$address['addr'];
                    if ($addrType === 'ipv4') break;
                }
            }
            if (!$ip) continue;

            $hostname = isset($host->hostnames->hostname[0]) ? trim((string)$host->hostnames->hostname[0]['name']) : '';
            $assetName = $hostname !== '' ? $hostname : $ip;
            $osPlatform = isset($host->os->osmatch[0]) ? trim((string)$host->os->osmatch[0]['name']) : null;

            $find = $db->prepare('SELECT assetID FROM assets WHERE ipAddress = :ip LIMIT 1');
            $find->execute([':ip' => $ip]);
            $assetID = (int)($find->fetchColumn() ?: 0);
            if ($assetID <= 0) {
                $insert = $db->prepare(
                    "INSERT INTO assets (assetName, assetType, ipAddress, osPlatform, criticality, environment)
                     VALUES (:name, 'Network_Device', :ip, :os, 'Medium', 'Production')"
                );
                $insert->execute([':name'=>$assetName, ':ip'=>$ip, ':os'=>$osPlatform]);
                $assetID = (int)$db->lastInsertId();
                logAction('DISCOVER', 'assets', $assetID, 'Discovered by Nmap at ' . $ip);
            } else {
                $db->prepare('UPDATE assets SET osPlatform = COALESCE(:os, osPlatform) WHERE assetID = :id')
                    ->execute([':os'=>$osPlatform, ':id'=>$assetID]);
            }
            $hostCount++;

            if (isset($host->ports->port)) {
                foreach ($host->ports->port as $port) {
                    $protocol = strtolower((string)$port['protocol']);
                    if (!in_array($protocol, ['tcp','udp'], true)) continue;
                    $portNo = (int)$port['portid'];
                    if ($portNo < 1 || $portNo > 65535) continue;

                    $state = isset($port->state) ? (string)$port->state['state'] : null;
                    if ($state !== 'open') continue;
                    $serviceName = isset($port->service) ? (string)$port->service['name'] : null;
                    $product = isset($port->service) ? (string)$port->service['product'] : null;
                    $version = isset($port->service) ? (string)$port->service['version'] : null;
                    $cpe = isset($port->service->cpe[0]) ? trim((string)$port->service->cpe[0]) : null;

                    $service = $db->prepare(
                        'INSERT INTO asset_services
                            (assetID, protocol, port, state, serviceName, product, version, cpe, isActive, lastSeenScanRunID)
                         VALUES (:asset, :protocol, :port, :state, :name, :product, :version, :cpe, 1, :scan)
                         ON DUPLICATE KEY UPDATE
                            state=VALUES(state), serviceName=VALUES(serviceName), product=VALUES(product),
                            version=VALUES(version), cpe=VALUES(cpe), isActive=1,
                            lastSeen=CURRENT_TIMESTAMP, lastSeenScanRunID=VALUES(lastSeenScanRunID)'
                    );
                    $service->execute([
                        ':asset'=>$assetID, ':protocol'=>$protocol, ':port'=>$portNo, ':state'=>'open',
                        ':name'=>$serviceName ?: null, ':product'=>$product ?: null, ':version'=>$version ?: null,
                        ':cpe'=>$cpe ?: null, ':scan'=>$scanRunID,
                    ]);
                    $serviceCount++;
                }
            }

            $retire = $db->prepare(
                'UPDATE asset_services
                 SET isActive = 0
                 WHERE assetID = :asset AND isActive = 1
                   AND (lastSeenScanRunID IS NULL OR lastSeenScanRunID <> :scan)'
            );
            $retire->execute([':asset'=>$assetID, ':scan'=>$scanRunID]);
            $retiredServiceCount += $retire->rowCount();
        }

        $db->prepare("UPDATE scan_runs SET status='Succeeded', hostsObserved=:hosts, completedAt=CURRENT_TIMESTAMP WHERE scanRunID=:id")
            ->execute([':hosts'=>$hostCount, ':id'=>$scanRunID]);
    } catch (Throwable $ex) {
        $db->prepare("UPDATE scan_runs SET status='Failed', completedAt=CURRENT_TIMESTAMP, errorMessage=:error WHERE scanRunID=:id")
            ->execute([':error'=>$ex->getMessage(), ':id'=>$scanRunID]);
        throw $ex;
    }

    return ['scan_run_id'=>$scanRunID, 'hosts'=>$hostCount, 'services'=>$serviceCount, 'services_retired'=>$retiredServiceCount];
}
