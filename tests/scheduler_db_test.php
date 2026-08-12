<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/scheduler.php';

$tests=0;
function schedulerdbcheck(bool $ok,string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR,"FAIL: {$message}\n"); exit(1); }
}

$db1=getDB();
$dsn=sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',DB_HOST,DB_PORT,DB_NAME);
$db2=new PDO($dsn,DB_USER,DB_PASS,[
    PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES=>false,
]);
releaseCycleLock($db1);
releaseCycleLock($db2);

schedulerdbcheck(tryAcquireCycleLock($db1)===true,'first scheduler connection acquires cycle lock');
schedulerdbcheck(tryAcquireCycleLock($db2)===false,'second scheduler connection cannot overlap active cycle');
releaseCycleLock($db1);
schedulerdbcheck(tryAcquireCycleLock($db2)===true,'cycle lock becomes available after owner releases it');
releaseCycleLock($db2);

$runID=createCycleRun($db1,'scheduler-test-worker');
schedulerdbcheck($runID>0,'running cycle telemetry row is created');
$row=$db1->query("SELECT status,completedAt FROM continuous_cycle_runs WHERE cycleRunID={$runID}")->fetch();
schedulerdbcheck($row['status']==='Running' && $row['completedAt']===null,'running cycle remains nonterminal');
$summary=['cycle_run_id'=>$runID,'worker_id'=>'scheduler-test-worker','finished_at'=>gmdate(DATE_ATOM)];
finishCycleRun($db1,$runID,'Succeeded',$summary);
$row=$db1->query("SELECT status,completedAt,summaryJson FROM continuous_cycle_runs WHERE cycleRunID={$runID}")->fetch();
schedulerdbcheck($row['status']==='Succeeded' && $row['completedAt']!==null,'terminal cycle telemetry records completion');
schedulerdbcheck((json_decode((string)$row['summaryJson'],true)['cycle_run_id'] ?? null)===$runID,'cycle summary is persisted as JSON');

$db1->prepare(
    "INSERT INTO distribution_advisory_sync_runs
        (provider,dataSourceIdentifier,sourceUrl,status,recordsProcessed,recordsStored,startedAt,completedAt)
     VALUES ('SchedulerFixture','scheduler-fixture','https://example.invalid/feed','Succeeded',1000,1000,
             CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"
)->execute();
$fresh=packageAdvisorySyncDue($db1,24,'SchedulerFixture');
schedulerdbcheck($fresh['due']===false && $fresh['reason']==='fresh','recent successful provider sync is not due');
$db1->exec("UPDATE distribution_advisory_sync_runs SET completedAt=DATE_SUB(CURRENT_TIMESTAMP,INTERVAL 48 HOUR) WHERE provider='SchedulerFixture'");
$due=packageAdvisorySyncDue($db1,24,'SchedulerFixture');
schedulerdbcheck($due['due']===true && $due['reason']==='cadence_elapsed','stale successful provider sync becomes due');
$disabled=packageAdvisorySyncDue($db1,0,'SchedulerFixture');
schedulerdbcheck($disabled['due']===false && $disabled['reason']==='disabled','zero cadence disables automatic provider sync');

$skipped=createCycleRun($db1,'scheduler-overlap-test','Skipped',json_encode(['skipped'=>'overlap']),'lock busy');
$row=$db1->query("SELECT status,completedAt,errorMessage FROM continuous_cycle_runs WHERE cycleRunID={$skipped}")->fetch();
schedulerdbcheck($row['status']==='Skipped' && $row['completedAt']!==null && $row['errorMessage']==='lock busy','skipped overlap attempt is visible operationally');

echo "PASS: {$tests} scheduler database tests\n";
