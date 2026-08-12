<?php
/** Bounded argv-array subprocess execution with optional heartbeat callbacks. */

function runBoundedProcess(
    array $argv,
    int $timeoutSeconds = 60,
    int $maxOutputBytes = 67108864,
    ?callable $heartbeat = null,
    int $heartbeatIntervalSeconds = 15
): array {
    if (!$argv || !is_string($argv[0]) || trim($argv[0]) === '') {
        throw new InvalidArgumentException('Process argv must contain an executable.');
    }
    $timeoutSeconds = max(1, min(3600, $timeoutSeconds));
    $maxOutputBytes = max(1024, min(268435456, $maxOutputBytes));
    $heartbeatIntervalSeconds = max(1, min(300, $heartbeatIntervalSeconds));

    $descriptor = [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']];
    $process = proc_open($argv, $descriptor, $pipes);
    if (!is_resource($process)) throw new RuntimeException('Unable to launch subprocess.');
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

    $stdout = ''; $stderr = '';
    $started = microtime(true);
    $nextHeartbeat = $started + $heartbeatIntervalSeconds;
    $timedOut = false; $outputExceeded = false;
    $observedExit = null;

    try {
        while (true) {
            $stdoutChunk = stream_get_contents($pipes[1]);
            $stderrChunk = stream_get_contents($pipes[2]);
            if ($stdoutChunk !== false && $stdoutChunk !== '') $stdout .= $stdoutChunk;
            if ($stderrChunk !== false && $stderrChunk !== '') $stderr .= $stderrChunk;
            if (strlen($stdout) + strlen($stderr) > $maxOutputBytes) {
                $outputExceeded = true;
                proc_terminate($process, 15);
                usleep(200000);
                $status = proc_get_status($process);
                if ($status['running'] ?? false) proc_terminate($process, 9);
                break;
            }

            $status = proc_get_status($process);
            if (!($status['running'] ?? false)) {
                if (isset($status['exitcode']) && (int)$status['exitcode'] >= 0) $observedExit = (int)$status['exitcode'];
                break;
            }

            $now = microtime(true);
            if ($heartbeat !== null && $now >= $nextHeartbeat) {
                $heartbeat();
                $nextHeartbeat = $now + $heartbeatIntervalSeconds;
            }
            if (($now - $started) >= $timeoutSeconds) {
                $timedOut = true;
                proc_terminate($process, 15);
                usleep(200000);
                $status = proc_get_status($process);
                if ($status['running'] ?? false) proc_terminate($process, 9);
                break;
            }
            usleep(100000);
        }

        $tail = stream_get_contents($pipes[1]);
        if ($tail !== false && $tail !== '') $stdout .= $tail;
        $tail = stream_get_contents($pipes[2]);
        if ($tail !== false && $tail !== '') $stderr .= $tail;
    } finally {
        fclose($pipes[1]); fclose($pipes[2]);
    }

    $exit = proc_close($process);
    if ($exit < 0 && $observedExit !== null) $exit = $observedExit;
    if ($timedOut) $exit = 124;
    if ($outputExceeded) $exit = 125;
    return [
        'exit'=>$exit,
        'stdout'=>$stdout,
        'stderr'=>$stderr,
        'timed_out'=>$timedOut,
        'output_exceeded'=>$outputExceeded,
        'duration_seconds'=>round(microtime(true) - $started, 3),
    ];
}
