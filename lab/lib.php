<?php
/** Shared isolation and assertion helpers for the disposable pilot lab. */

function ctvlmsLabAssertIsolation(): void
{
    if (getenv('CTVLMS_LAB_MODE') !== '1') {
        throw new RuntimeException('Refusing: CTVLMS_LAB_MODE=1 is required.');
    }
    if (DB_HOST !== '127.0.0.1' || (int)DB_PORT !== 33306 || DB_NAME !== 'ctvlms') {
        throw new RuntimeException('Refusing: pilot lab must use isolated MariaDB at 127.0.0.1:33306/ctvlms.');
    }
    if (DB_USER !== 'ctvlms_lab_app') {
        throw new RuntimeException('Refusing: unexpected pilot-lab database user.');
    }
}

function ctvlmsLabCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException('LAB ASSERTION FAILED: ' . $message);
    fwrite(STDOUT, "PASS: {$message}\n");
}

function ctvlmsLabAssetMap(PDO $db): array
{
    $rows = $db->query(
        "SELECT assetID,assetName,ipAddress FROM assets
         WHERE assetName IN (
            'ctvlms-lab-canary','ctvlms-lab-general','ctvlms-lab-stale',
            'ctvlms-lab-failure','ctvlms-lab-cancel'
         )"
    )->fetchAll();
    $out = [];
    foreach ($rows as $row) $out[(string)$row['assetName']] = $row;
    return $out;
}

function ctvlmsLabRun(array $argv, bool $allowFailure = false, int $timeoutSeconds = 600): array
{
    $descriptor = [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
    $proc = proc_open($argv,$descriptor,$pipes,null,null,['bypass_shell'=>true]);
    if (!is_resource($proc)) throw new RuntimeException('Unable to start child process.');
    fclose($pipes[0]);
    stream_set_blocking($pipes[1],false);
    stream_set_blocking($pipes[2],false);
    $stdout=''; $stderr=''; $started=microtime(true);
    while (true) {
        $stdout .= stream_get_contents($pipes[1]);
        $stderr .= stream_get_contents($pipes[2]);
        $status = proc_get_status($proc);
        if (!$status['running']) break;
        if (microtime(true)-$started > $timeoutSeconds) {
            proc_terminate($proc,15);
            usleep(250000);
            $status=proc_get_status($proc);
            if ($status['running']) proc_terminate($proc,9);
            fclose($pipes[1]); fclose($pipes[2]); proc_close($proc);
            throw new RuntimeException('Child process timed out: ' . implode(' ',array_map('strval',$argv)));
        }
        usleep(50000);
    }
    $stdout .= stream_get_contents($pipes[1]);
    $stderr .= stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    $exit = proc_close($proc);
    // proc_close can return -1 after proc_get_status has observed termination;
    // preserve the last status exit code in that case.
    if ($exit === -1 && isset($status['exitcode']) && $status['exitcode'] >= 0) $exit=(int)$status['exitcode'];
    if (!$allowFailure && $exit !== 0) {
        throw new RuntimeException(
            'Child failed (' . $exit . '): ' . implode(' ',array_map('strval',$argv)) . "\n" . trim($stderr ?: $stdout)
        );
    }
    return ['exit'=>$exit,'stdout'=>$stdout,'stderr'=>$stderr];
}
