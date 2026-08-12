<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/health.php';

$health=ctvlmsReadiness(getDB());
if ($health !== ['status'=>'ok']) {
    fwrite(STDERR,"FAIL: database readiness should return only status=ok\n");
    exit(1);
}
echo "PASS: 1 readiness database test\n";
