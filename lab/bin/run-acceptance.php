#!/usr/bin/env php
<?php
$root=dirname(__DIR__,2);
chdir($root);
require_once $root . '/config/config.php';
require_once $root . '/config/database.php';
require_once $root . '/includes/package_engine_v2.php';
require_once $root . '/includes/remediation.php';
require_once $root . '/includes/remediation_queue.php';
require_once $root . '/includes/ssh_transport.php';
require_once $root . '/includes/verification.php';
require_once __DIR__ . '/../lib.php';

ctvlmsLabAssertIsolation();
$db=getDB();
$assets=ctvlmsLabAssetMap($db);
foreach (['ctvlms-lab-canary','ctvlms-lab-general','ctvlms-lab-stale','ctvlms-lab-failure','ctvlms-lab-cancel'] as $name) {
    ctvlmsLabCheck(isset($assets[$name]),"bootstrap created {$name}");
}

function labAssetID(array $assets,string $name): int { return (int)$assets[$name]['assetID']; }
function labInventory(int $assetID,string $root): void {
    $result=ctvlmsLabRun([PHP_BINARY,$root.'/bin/inventory-ssh.php',(string)$assetID],false,360);
    ctvlmsLabCheck(str_contains($result['stdout'],'"transport": "SSH"') || str_contains($result['stdout'],'"transport":"SSH"'),"SSH inventory succeeded for asset {$assetID}");
}
function labPackageVersion(PDO $db,int $assetID): string {
    $stmt=$db->prepare("SELECT binaryVersion FROM asset_package_inventory WHERE assetID=:asset AND binaryPackage='ctvlms-lab-pkg' AND isActive=1 LIMIT 1");
    $stmt->execute([':asset'=>$assetID]);
    return (string)$stmt->fetchColumn();
}
function labJob(PDO $db,int $assetID): array {
    $stmt=$db->prepare("SELECT j.*,e.exposureID,e.status AS exposureStatus FROM remediation_jobs j JOIN exposure_matches e ON e.exposureID=j.exposureID WHERE j.assetID=:asset AND j.packageName='ctvlms-lab-pkg' ORDER BY j.jobID DESC LIMIT 1");
    $stmt->execute([':asset'=>$assetID]);
    $row=$stmt->fetch();
    if (!$row) throw new RuntimeException("No lab remediation job for asset {$assetID}");
    return $row;
}
function labExposureStatus(PDO $db,int $exposureID): string {
    $stmt=$db->prepare('SELECT status FROM exposure_matches WHERE exposureID=:id');
    $stmt->execute([':id'=>$exposureID]);
    return (string)$stmt->fetchColumn();
}
function labReleaseJob(PDO $db,int $jobID,?string $status=null): void {
    if ($status!==null) {
        $stmt=$db->prepare("UPDATE remediation_jobs SET status=:status,nextAttemptAt=NULL,approvedAt=CASE WHEN :status2='Approved' THEN CURRENT_TIMESTAMP ELSE approvedAt END WHERE jobID=:job");
        $stmt->execute([':status'=>$status,':status2'=>$status,':job'=>$jobID]);
    } else {
        $db->prepare('UPDATE remediation_jobs SET nextAttemptAt=NULL WHERE jobID=:job')->execute([':job'=>$jobID]);
    }
}
function labRunPatchWorker(string $root,bool $expectSuccess): array {
    $result=ctvlmsLabRun([PHP_BINARY,$root.'/bin/patch-worker.php'],true,240);
    if ($expectSuccess) {
        ctvlmsLabCheck($result['exit']===0,'patch worker completed successfully');
    } else {
        ctvlmsLabCheck($result['exit']!==0,'patch worker rejected/failed the unsafe scenario');
    }
    return $result;
}
function labDirectUpgrade(PDO $db,int $assetID): void {
    $stmt=$db->prepare("SELECT a.ipAddress,p.sshUser,p.sshKeyEnv,p.sshKnownHostsEnv FROM assets a JOIN asset_patch_policies p ON p.assetID=a.assetID WHERE a.assetID=:asset");
    $stmt->execute([':asset'=>$assetID]);
    $policy=$stmt->fetch();
    if (!$policy) throw new RuntimeException('Missing patch policy for out-of-band change setup.');
    [, $upgrade]=packageCommands('apt','ctvlms-lab-pkg');
    $argv=buildStrictSshArgv(
        (string)$policy['ipAddress'],(string)$policy['sshUser'],
        requiredFileFromEnv((string)$policy['sshKeyEnv'],'lab SSH key'),
        requiredFileFromEnv((string)$policy['sshKnownHostsEnv'],'lab known-hosts'),
        $upgrade,5
    );
    $result=runBoundedProcess($argv,120,16777216);
    ctvlmsLabCheck($result['exit']===0,'out-of-band package change succeeded');
}

$canary=labAssetID($assets,'ctvlms-lab-canary');
$general=labAssetID($assets,'ctvlms-lab-general');
$stale=labAssetID($assets,'ctvlms-lab-stale');
$failure=labAssetID($assets,'ctvlms-lab-failure');
$cancel=labAssetID($assets,'ctvlms-lab-cancel');

fwrite(STDOUT,"\n== 1. Authoritative remote inventory ==\n");
foreach ([$canary,$general,$stale,$failure,$cancel] as $assetID) {
    labInventory($assetID,$root);
    ctvlmsLabCheck(labPackageVersion($db,$assetID)==='1.0',"asset {$assetID} starts on lab package 1.0");
}

fwrite(STDOUT,"\n== 2. Advisory applicability and queueing ==\n");
$evaluation=evaluatePackageAdvisoriesV2($db);
ctvlmsLabCheck((int)$evaluation['confirmed']===5,'native Debian lab advisory confirms exactly five affected endpoints');
ctvlmsLabCheck((int)$evaluation['materialized_advisory_findings']===5,'exactly five authoritative package findings are materialized');
$queued=queueEligibleRemediationJobs($db);
ctvlmsLabCheck($queued===5,'five remediation jobs created through normal policy gate');
$db->exec("UPDATE remediation_jobs SET nextAttemptAt=DATE_ADD(CURRENT_TIMESTAMP,INTERVAL 1 DAY) WHERE packageName='ctvlms-lab-pkg' AND status IN ('Queued','Approved')");

$canaryJob=labJob($db,$canary);
$generalJob=labJob($db,$general);
$staleJob=labJob($db,$stale);
$failureJob=labJob($db,$failure);
$cancelJob=labJob($db,$cancel);
ctvlmsLabCheck($canaryJob['status']==='Queued','Auto canary job is queued');
ctvlmsLabCheck($generalJob['status']==='Awaiting_Approval','approval-mode endpoint requires operator approval');

fwrite(STDOUT,"\n== 3. Canary patch across the real two-cycle verification order ==\n");
labReleaseJob($db,(int)$canaryJob['jobID']);
labRunPatchWorker($root,true);
$canaryJob=labJob($db,$canary);
ctvlmsLabCheck($canaryJob['status']==='Succeeded','canary remediation job succeeded');
labInventory($canary,$root);
ctvlmsLabCheck(labPackageVersion($db,$canary)==='1.1','fresh inventory observes canary package 1.1');
$canaryCorrelation=evaluatePackageAdvisoriesV2($db,$canary);
ctvlmsLabCheck((int)$canaryCorrelation['not_affected']===1,'next-cycle correlation sees the patched canary as not affected');
ctvlmsLabCheck(labExposureStatus($db,(int)$canaryJob['exposureID'])==='Remediated','correlation preserves Remediated until verification consumes fresh evidence');
ctvlmsLabCheck(verifyRemediatedExposure($db,(int)$canaryJob['exposureID'])===true,'canary closes only after fresh post-patch inventory');
evaluatePackageAdvisoriesV2($db,$canary);
ctvlmsLabCheck(labExposureStatus($db,(int)$canaryJob['exposureID'])==='Verified_Closed','later correlation preserves Verified_Closed while evidence remains not affected');

fwrite(STDOUT,"\n== 4. Approval + expired worker lease recovery ==\n");
$db->exec("UPDATE remediation_rollout_groups SET phase='General',pausedReason=NULL WHERE groupName='ctvlms-lab-primary'");
labReleaseJob($db,(int)$generalJob['jobID'],'Approved');
$abandoned=claimRemediationJob($db,'ctvlms-lab-abandoned-worker',60);
ctvlmsLabCheck($abandoned!==null && (int)$abandoned['jobID']===(int)$generalJob['jobID'],'general job claimed by simulated worker');
$db->prepare('UPDATE remediation_jobs SET leasedUntil=DATE_SUB(CURRENT_TIMESTAMP,INTERVAL 1 SECOND) WHERE jobID=:job')->execute([':job'=>$generalJob['jobID']]);
labRunPatchWorker($root,true);
$generalJob=labJob($db,$general);
ctvlmsLabCheck($generalJob['status']==='Succeeded','expired lease was safely reclaimed and job completed');
ctvlmsLabCheck((int)$generalJob['attemptCount']===2,'reclaimed job records both worker attempts');
labInventory($general,$root);
evaluatePackageAdvisoriesV2($db,$general);
ctvlmsLabCheck(labExposureStatus($db,(int)$generalJob['exposureID'])==='Remediated','reclaimed remediation also survives correlation-before-verification ordering');
ctvlmsLabCheck(verifyRemediatedExposure($db,(int)$generalJob['exposureID'])===true,'reclaimed remediation verifies closed from fresh inventory');

fwrite(STDOUT,"\n== 5. Stale evaluated version fence ==\n");
labDirectUpgrade($db,$stale);
labReleaseJob($db,(int)$staleJob['jobID']);
labRunPatchWorker($root,false);
$staleJob=labJob($db,$stale);
ctvlmsLabCheck($staleJob['status']==='Failed','stale remediation job is failed instead of patching blindly');
ctvlmsLabCheck($staleJob['lastFailureClass']==='inventory_changed','stale job records inventory_changed failure class');
labInventory($stale,$root);
ctvlmsLabCheck(labPackageVersion($db,$stale)==='1.1','fresh inventory captures the out-of-band package change');
$staleEval=evaluatePackageAdvisoriesV2($db,$stale);
ctvlmsLabCheck((int)$staleEval['not_affected']===1,'fresh applicability resolves externally updated endpoint as not affected');

fwrite(STDOUT,"\n== 6. Applicability change cancels queued remediation ==\n");
labDirectUpgrade($db,$cancel);
labInventory($cancel,$root);
ctvlmsLabCheck(labPackageVersion($db,$cancel)==='1.1','cancellation target fresh inventory observes external fixed version');
$cancelEval=evaluatePackageAdvisoriesV2($db,$cancel);
ctvlmsLabCheck((int)$cancelEval['not_affected']===1,'fresh correlation resolves queued target as not affected');
$cancelJob=labJob($db,$cancel);
ctvlmsLabCheck($cancelJob['status']==='Cancelled','queued remediation is cancelled instead of remaining stuck or patching unnecessarily');
ctvlmsLabCheck($cancelJob['lastFailureClass']==='applicability_changed','cancelled job records applicability_changed reason');
ctvlmsLabCheck($cancelJob['exposureStatus']==='Not_Affected','cancelled job keeps authoritative Not_Affected exposure state');

fwrite(STDOUT,"\n== 7. Failed patch auto-pauses rollout ==\n");
labReleaseJob($db,(int)$failureJob['jobID']);
labRunPatchWorker($root,false);
$failureJob=labJob($db,$failure);
ctvlmsLabCheck($failureJob['status']==='Failed','unpatchable endpoint produces a failed remediation job');
ctvlmsLabCheck(in_array($failureJob['lastFailureClass'],['upgrade_failed','no_version_change'],true),'failure is classified as a concrete patch failure');
$phase=(string)$db->query("SELECT phase FROM remediation_rollout_groups WHERE groupName='ctvlms-lab-failure'")->fetchColumn();
ctvlmsLabCheck($phase==='Paused','failed remediation automatically pauses its rollout group');
$paused=(int)$db->query("SELECT COUNT(*) FROM remediation_rollout_events re JOIN remediation_rollout_groups rg ON rg.groupID=re.groupID WHERE rg.groupName='ctvlms-lab-failure' AND re.eventType='Auto_Paused'")->fetchColumn();
ctvlmsLabCheck($paused===1,'rollout auto-pause is auditable');
ctvlmsLabCheck(labPackageVersion($db,$failure)==='1.0','failed endpoint remains on version 1.0');

$summary=$db->query(
    "SELECT a.assetName,j.status AS jobStatus,e.status AS exposureStatus,av.status AS lifecycleStatus,
            j.attemptCount,j.lastFailureClass
     FROM assets a
     JOIN remediation_jobs j ON j.assetID=a.assetID
     JOIN exposure_matches e ON e.exposureID=j.exposureID
     JOIN asset_vulnerabilities av ON av.assetID=e.assetID AND av.vulnID=e.vulnID
     WHERE a.assetName LIKE 'ctvlms-lab-%'
     ORDER BY a.assetName"
)->fetchAll();

fwrite(STDOUT,"\n== Pilot lab result ==\n");
echo json_encode([
    'status'=>'PASS',
    'advisory'=>'CVE-2099-7701 (synthetic lab-only)',
    'package'=>'ctvlms-lab-pkg',
    'from_version'=>'1.0',
    'fixed_version'=>'1.1',
    'scenarios'=>$summary,
],JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
fwrite(STDOUT,"ALL PILOT LAB ACCEPTANCE GATES PASSED\n");
