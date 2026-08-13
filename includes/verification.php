<?php
/** Post-remediation verification requiring evidence newer than patch completion. */
require_once __DIR__ . '/audit.php';
require_once __DIR__ . '/exposure.php';
require_once __DIR__ . '/package_engine_v2.php';

function recordVerificationFailure(PDO $db, array $exposure, int $exposureID, array $evidence): bool
{
    $json=json_encode($evidence,JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    $db->prepare(
        "UPDATE exposure_matches SET status='Verification_Failed',evidence=:evidence,lastEvaluated=CURRENT_TIMESTAMP
         WHERE exposureID=:id"
    )->execute([':evidence'=>$json,':id'=>$exposureID]);
    $db->prepare(
        "UPDATE asset_vulnerabilities SET status='Remediation_In_Progress',closedDate=NULL
         WHERE assetVulnID=:id AND status='Remediated'"
    )->execute([':id'=>$exposure['assetVulnID']]);
    logAction('VERIFY_FAILED','exposure_matches',$exposureID,(string)($evidence['result'] ?? 'Verification failed'));
    return false;
}

function closeVerifiedExposure(PDO $db, array $exposure, int $exposureID, array $evidence): bool
{
    $json=json_encode($evidence,JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    $db->beginTransaction();
    try {
        $db->prepare(
            "INSERT INTO remediation_verifications (remediationID,verifierType,verifiedByUserID,evidence)
             VALUES (:remediation,'Automated',NULL,:evidence)
             ON DUPLICATE KEY UPDATE verifierType='Automated',verifiedByUserID=NULL,
                evidence=VALUES(evidence),verifiedAt=CURRENT_TIMESTAMP"
        )->execute([':remediation'=>$exposure['remediationID'],':evidence'=>$json]);
        $db->prepare(
            "UPDATE exposure_matches SET status='Verified_Closed',evidence=:evidence,lastEvaluated=CURRENT_TIMESTAMP
             WHERE exposureID=:id"
        )->execute([':evidence'=>$json,':id'=>$exposureID]);
        $db->prepare(
            "UPDATE asset_vulnerabilities SET status='Verified_Closed',closedDate=CURDATE()
             WHERE assetVulnID=:id AND status='Remediated'"
        )->execute([':id'=>$exposure['assetVulnID']]);
        logAction('AUTO_VERIFY','remediations',(int)$exposure['remediationID'],'Fresh post-patch evidence verified exposure closed');
        logAction('STATUS_CHANGE','asset_vulnerabilities',(int)$exposure['assetVulnID'],'Status: Remediated → Verified_Closed after fresh inventory');
        $db->commit();
        return true;
    } catch (Throwable $error) {
        if ($db->inTransaction()) $db->rollBack();
        throw $error;
    }
}

function freshSuccessfulInventoryRun(PDO $db, int $assetID, string $completedAt): ?array
{
    $stmt=$db->prepare(
        "SELECT inventoryRunID,transport,inventorySource,completedAt
         FROM inventory_runs
         WHERE assetID=:asset AND status='Succeeded' AND completedAt>=:completed
         ORDER BY completedAt DESC,inventoryRunID DESC LIMIT 1"
    );
    $stmt->execute([':asset'=>$assetID,':completed'=>$completedAt]);
    $row=$stmt->fetch();
    return $row ?: null;
}

function verifyPackageAdvisoryRemediation(PDO $db, array $exposure, int $exposureID): bool
{
    $freshRun=freshSuccessfulInventoryRun($db,(int)$exposure['assetID'],(string)$exposure['jobCompletedAt']);
    if ($freshRun===null) return false;

    $job=$db->prepare(
        "SELECT packageName FROM remediation_jobs
         WHERE exposureID=:exposure AND status='Succeeded' ORDER BY completedAt DESC LIMIT 1"
    );
    $job->execute([':exposure'=>$exposureID]);
    $packageName=(string)$job->fetchColumn();
    if ($packageName==='') return false;

    $current=$db->prepare(
        "SELECT p.* FROM asset_package_inventory p
         JOIN asset_software s ON s.softwareID=p.softwareID AND s.isActive=1
         WHERE p.assetID=:asset AND p.binaryPackage=:package AND p.isActive=1
         ORDER BY p.lastSeen DESC LIMIT 1"
    );
    $current->execute([':asset'=>$exposure['assetID'],':package'=>$packageName]);
    $package=$current->fetch();

    if (!$package) {
        return closeVerifiedExposure($db,$exposure,$exposureID,[
            'result'=>'package_absent_after_remediation',
            'package'=>$packageName,
            'inventory_run_id'=>(int)$freshRun['inventoryRunID'],
            'inventory_completed_at'=>$freshRun['completedAt'],
            'verified_at'=>gmdate(DATE_ATOM),
        ]);
    }
    if (strtotime((string)$package['lastSeen']) < strtotime((string)$exposure['jobCompletedAt'])) return false;

    $advisory=$db->prepare(
        "SELECT a.* FROM package_exposure_advisories pea
         JOIN distribution_advisories a ON a.advisoryID=pea.advisoryID
         WHERE pea.exposureID=:exposure LIMIT 1"
    );
    $advisory->execute([':exposure'=>$exposureID]);
    $rule=$advisory->fetch();
    if (!$rule) {
        return recordVerificationFailure($db,$exposure,$exposureID,[
            'result'=>'package_advisory_missing_after_remediation',
            'package'=>$packageName,'verified_at'=>gmdate(DATE_ATOM),
        ]);
    }

    $context=packageDistributionContext($db,(int)$exposure['assetID']);
    $mappings=packageAdvisoryMappings($db,$context);
    $authority=packageAdvisoryAuthority($rule,$context,$mappings);
    if ($authority===null) {
        return recordVerificationFailure($db,$exposure,$exposureID,[
            'result'=>'package_advisory_authority_lost',
            'package'=>$packageName,'provider'=>$rule['provider'],
            'distribution'=>$context,'verified_at'=>gmdate(DATE_ATOM),
        ]);
    }

    $result=packageAdvisoryApplicabilityAuthoritativeV2($package,$rule,$context,$authority);
    $evidence=$result['evidence'];
    $evidence['comparison_result']=$result['comparison_result'];
    $evidence['reason']=$result['reason'];
    $evidence['inventory_run_id']=(int)$freshRun['inventoryRunID'];
    $evidence['inventory_completed_at']=$freshRun['completedAt'];
    $evidence['verified_at']=gmdate(DATE_ATOM);

    if ($result['status']==='Not_Affected') {
        $evidence['result']='package_not_affected_after_remediation';
        return closeVerifiedExposure($db,$exposure,$exposureID,$evidence);
    }
    $evidence['result']=$result['status']==='Confirmed' ? 'package_still_affected' : 'package_applicability_unresolved';
    return recordVerificationFailure($db,$exposure,$exposureID,$evidence);
}

function verifyCpeRemediation(PDO $db, array $exposure, int $exposureID): bool
{
    $inventory=null;
    if (!empty($exposure['softwareID'])) {
        $stmt=$db->prepare('SELECT cpe,version,lastSeen FROM asset_software WHERE softwareID=:id');
        $stmt->execute([':id'=>$exposure['softwareID']]);
        $inventory=$stmt->fetch();
    } elseif (!empty($exposure['serviceID'])) {
        $stmt=$db->prepare('SELECT cpe,version,lastSeen FROM asset_services WHERE serviceID=:id');
        $stmt->execute([':id'=>$exposure['serviceID']]);
        $inventory=$stmt->fetch();
    }
    if (!$inventory || empty($inventory['cpe']) || empty($inventory['lastSeen'])) return false;
    if (strtotime((string)$inventory['lastSeen']) < strtotime((string)$exposure['jobCompletedAt'])) return false;

    $rules=$db->prepare('SELECT * FROM vulnerability_cpe_matches WHERE vulnID=:vuln AND vulnerable=1');
    $rules->execute([':vuln'=>$exposure['vulnID']]);
    $stillAffected=[];
    foreach ($rules->fetchAll() as $rule) {
        $match=evaluateCpeRule($inventory['cpe'],$rule,$inventory['version'] ?? null);
        if ($match!==null) {
            $stillAffected[]=[
                'criteria'=>$rule['criteria'],'match_type'=>$match['type'],
                'confidence'=>$match['confidence'],'status'=>$match['status'],
            ];
        }
    }
    if ($stillAffected) {
        return recordVerificationFailure($db,$exposure,$exposureID,[
            'result'=>'still_affected','observed_cpe'=>$inventory['cpe'],
            'observed_version'=>$inventory['version'],'matches'=>$stillAffected,
            'verified_at'=>gmdate(DATE_ATOM),
        ]);
    }
    return closeVerifiedExposure($db,$exposure,$exposureID,[
        'result'=>'not_affected_after_remediation','observed_cpe'=>$inventory['cpe'],
        'observed_version'=>$inventory['version'],'inventory_last_seen'=>$inventory['lastSeen'],
        'verified_at'=>gmdate(DATE_ATOM),
    ]);
}

/** Verify one remediated exposure only from evidence newer than job completion. */
function verifyRemediatedExposure(PDO $db, int $exposureID): bool
{
    $stmt=$db->prepare(
        "SELECT e.*,j.remediationID,j.completedAt AS jobCompletedAt,av.assetVulnID
         FROM exposure_matches e
         JOIN remediation_jobs j ON j.exposureID=e.exposureID AND j.status='Succeeded'
         JOIN asset_vulnerabilities av ON av.assetID=e.assetID AND av.vulnID=e.vulnID
         WHERE e.exposureID=:id AND e.status IN ('Remediated','Verification_Failed')
         ORDER BY j.completedAt DESC LIMIT 1"
    );
    $stmt->execute([':id'=>$exposureID]);
    $exposure=$stmt->fetch();
    if (!$exposure || empty($exposure['remediationID']) || empty($exposure['jobCompletedAt'])) return false;
    if ($exposure['matchType']==='Package_Advisory') {
        return verifyPackageAdvisoryRemediation($db,$exposure,$exposureID);
    }
    return verifyCpeRemediation($db,$exposure,$exposureID);
}
