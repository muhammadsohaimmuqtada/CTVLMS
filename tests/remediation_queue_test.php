<?php
require_once __DIR__ . '/../includes/remediation_queue.php';

$tests=0;
function queuecheck(bool $ok,string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR,"FAIL: {$message}\n"); exit(1); }
}
$utc=new DateTimeZone('UTC');
$policy=[
    'maintenanceTimezone'=>'UTC','maintenanceDays'=>'mon,tue,wed,thu,fri',
    'maintenanceStart'=>'09:00:00','maintenanceEnd'=>'17:00:00',
];
queuecheck(maintenanceWindowAllows($policy,new DateTimeImmutable('2026-08-12 10:00:00',$utc)), 'weekday maintenance window allows execution');
queuecheck(!maintenanceWindowAllows($policy,new DateTimeImmutable('2026-08-12 18:00:00',$utc)), 'outside maintenance clock is blocked');
queuecheck(!maintenanceWindowAllows($policy,new DateTimeImmutable('2026-08-16 10:00:00',$utc)), 'disallowed weekday is blocked');

$overnight=[
    'maintenanceTimezone'=>'UTC','maintenanceDays'=>'mon',
    'maintenanceStart'=>'22:00:00','maintenanceEnd'=>'02:00:00',
];
queuecheck(maintenanceWindowAllows($overnight,new DateTimeImmutable('2026-08-10 23:30:00',$utc)), 'cross-midnight window allows start day');
queuecheck(maintenanceWindowAllows($overnight,new DateTimeImmutable('2026-08-11 01:30:00',$utc)), 'cross-midnight window carries previous allowed day');
queuecheck(!maintenanceWindowAllows($overnight,new DateTimeImmutable('2026-08-11 03:00:00',$utc)), 'cross-midnight window ends correctly');
queuecheck(maintenanceWindowAllows(['maintenanceStart'=>null,'maintenanceEnd'=>null]), 'null maintenance window is unrestricted');
queuecheck(!maintenanceWindowAllows(['maintenanceStart'=>'09:00:00','maintenanceEnd'=>null]), 'half-configured maintenance window fails closed');

queuecheck(remediationRetryDelaySeconds(1)===30, 'first retry delay is bounded');
queuecheck(remediationRetryDelaySeconds(2)===60, 'retry delay backs off');
queuecheck(remediationRetryDelaySeconds(10)===900, 'retry delay is capped');
queuecheck(maintenanceDaySet('mon,mon,tue')===['mon','tue'], 'maintenance days are normalized and deduplicated');

echo "PASS: {$tests} remediation queue policy tests\n";
