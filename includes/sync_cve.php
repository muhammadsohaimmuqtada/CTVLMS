<?php
// includes/sync_cve.php
// Fetches live CVEs from the NIST NVD API 2.0

function syncNistCVEs($db) {
    // NVD API 2.0 can be slow/rate-limited without a key. 
    // We'll fetch the most recently modified CVEs by using a recent date range.
    $endDate = new DateTime('now', new DateTimeZone('UTC'));
    $startDate = (clone $endDate)->modify('-2 days'); // Last 48 hours to minimize data volume
    
    $startStr = $startDate->format('Y-m-d\TH:i:s.000O');
    $startStr = substr_replace($startStr, ':', -2, 0); // Format to Y-m-dTH:i:s.000+00:00
    
    $endStr = $endDate->format('Y-m-d\TH:i:s.000O');
    $endStr = substr_replace($endStr, ':', -2, 0);

    $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=" . urlencode($startStr) . "&pubEndDate=" . urlencode($endStr) . "&resultsPerPage=20";
    
    $options = [
        "http" => [
            "method" => "GET",
            "header" => "User-Agent: CTVLMS-Student-Project/1.0\r\n" .
                        "Accept: application/json\r\n",
            "timeout" => 120, // NIST is extremely slow without an API key
            "ignore_errors" => true
        ]
    ];
    $maxRetries = 3;
    $retryDelay = 2; // seconds
    $json = false;
    
    for ($i = 0; $i <= $maxRetries; $i++) {
        $context = stream_context_create($options);
        $json = @file_get_contents($url, false, $context);
        
        if (isset($http_response_header) && is_array($http_response_header)) {
            $status_line = $http_response_header[0];
            
            // Check for success
            if (strpos($status_line, '200') !== false && $json) {
                break;
            }
            
            // On 503 Service Unavailable or 403 Forbidden rate limits, back off and retry
            if (strpos($status_line, '503') !== false || strpos($status_line, '403') !== false) {
                if ($i < $maxRetries) {
                    sleep($retryDelay);
                    $retryDelay *= 2; // 2, 4, 8 seconds...
                    continue;
                }
            }
        }
        
        // If we reach here and it's the last iteration, fail out
        if ($i === $maxRetries) {
            return false;
        }
    }
    
    $data = json_decode($json, true);
    if (!isset($data['vulnerabilities'])) {
        return false;
    }
    
    $addedCount = 0;
    
    $stmt = $db->prepare('INSERT INTO vulnerabilities (cveID, title, description, cvssScore, severity, publishedDate) 
                          VALUES (:cveID, :title, :description, :cvssScore, :severity, :publishedDate)
                          ON DUPLICATE KEY UPDATE 
                          title = VALUES(title), 
                          description = VALUES(description), 
                          cvssScore = VALUES(cvssScore), 
                          severity = VALUES(severity)');
    
    foreach ($data['vulnerabilities'] as $item) {
        $cve = $item['cve'];
        $cveID = $cve['id'] ?? null;
        if (!$cveID) continue;
        
        $desc = 'No description available';
        if (isset($cve['descriptions']) && is_array($cve['descriptions'])) {
            foreach ($cve['descriptions'] as $d) {
                if ($d['lang'] === 'en') {
                    $desc = $d['value'];
                    break;
                }
            }
        }
        
        // Create a reasonable title from the description
        $title = (strlen($desc) > 80) ? substr($desc, 0, 77) . '...' : $desc;
        
        $cvssScore = null;
        if (isset($cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'])) {
            $cvssScore = $cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'];
        } elseif (isset($cve['metrics']['cvssMetricV30'][0]['cvssData']['baseScore'])) {
            $cvssScore = $cve['metrics']['cvssMetricV30'][0]['cvssData']['baseScore'];
        } elseif (isset($cve['metrics']['cvssMetricV2'][0]['cvssData']['baseScore'])) {
            $cvssScore = $cve['metrics']['cvssMetricV2'][0]['cvssData']['baseScore'];
        }
        
        if ($cvssScore === null) {
            $severity = 'Low'; // Default for missing CVSS
        } else {
            $severity = 'Low';
            if ($cvssScore >= 9.0) $severity = 'Critical';
            elseif ($cvssScore >= 7.0) $severity = 'High';
            elseif ($cvssScore >= 4.0) $severity = 'Medium';
        }
        
        $pubDate = null;
        if (isset($cve['published'])) {
            $pubDate = date('Y-m-d', strtotime($cve['published']));
        }
        
        $stmt->execute([
            ':cveID' => $cveID,
            ':title' => $title,
            ':description' => $desc,
            ':cvssScore' => $cvssScore,
            ':severity' => $severity,
            ':publishedDate' => $pubDate
        ]);
        
        if ($stmt->rowCount() > 0) {
            $addedCount++;
            $newId = $db->lastInsertId();
            logAction('CREATE', 'vulnerabilities', $newId, "Synced from NIST API: $cveID");
        }
    }
    
    return $addedCount;
}

// Allow CLI execution
if (php_sapi_name() === 'cli') {
    require_once __DIR__ . '/../config/config.php';
    require_once __DIR__ . '/../config/database.php';
    require_once __DIR__ . '/audit.php';
    
    $db = getDB();
    echo "Syncing NIST CVEs (last 48 hours)...\n";
    $added = syncNistCVEs($db);
    if ($added === false) {
        echo "Failed to fetch data from NIST API.\n";
    } else {
        echo "Added $added new vulnerabilities.\n";
    }
}
