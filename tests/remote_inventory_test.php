<?php
require_once __DIR__ . '/../includes/inventory.php';
require_once __DIR__ . '/../includes/ssh_transport.php';

$tests = 0;
function remotecheck(bool $ok, string $message): void {
    global $tests; $tests++;
    if (!$ok) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

$argv = buildStrictSshArgv(
    '192.0.2.20','ctvlms-reader','/tmp/test-key','/tmp/test-known-hosts',
    inventorySshCommand('hostname'),12
);
remotecheck($argv[0] === 'ssh' && in_array('BatchMode=yes',$argv,true), 'SSH uses non-interactive argv execution');
remotecheck(in_array('StrictHostKeyChecking=yes',$argv,true), 'strict host-key checking is mandatory');
remotecheck(in_array('UserKnownHostsFile=/tmp/test-known-hosts',$argv,true), 'dedicated known-hosts file is explicit');
remotecheck($argv[count($argv)-2] === 'ctvlms-reader@192.0.2.20', 'validated user and IP form SSH target');
remotecheck($argv[count($argv)-1] === 'hostname', 'remote inventory command remains one fixed argv value');
remotecheck(str_contains(inventorySshCommand('packages'),'${binary:Package}'), 'dpkg probe preserves literal dpkg fields');

$rejected = false;
try { buildStrictSshArgv('192.0.2.20','-oProxyCommand=x','/k','/h','hostname'); }
catch (InvalidArgumentException) { $rejected = true; }
remotecheck($rejected, 'SSH option-like usernames are rejected');
$rejected = false;
try { inventorySshCommand('arbitrary'); } catch (InvalidArgumentException) { $rejected = true; }
remotecheck($rejected, 'only fixed inventory probes are available');

$facts = linuxFactsFromObservations(
    parseOsReleaseText("ID=debian\nPRETTY_NAME=\"Debian GNU/Linux 13\"\nVERSION_ID=13\nVERSION_CODENAME=trixie\nID_LIKE=debian\n"),
    "srv01\n","x86_64\n","6.12.0\n",'apt'
);
remotecheck($facts['os_id']==='debian' && $facts['distribution_suite']==='trixie', 'remote OS facts preserve distro and suite');
remotecheck($facts['hostname']==='srv01' && $facts['architecture']==='x86_64', 'remote host identity is normalized');

$process = runBoundedProcess([PHP_BINARY,'-r','fwrite(STDOUT,"ok");'],5,4096);
remotecheck($process['exit']===0 && $process['stdout']==='ok', 'bounded argv process preserves successful exit and output');
$process = runBoundedProcess([PHP_BINARY,'-r','usleep(1500000);'],1,4096);
remotecheck($process['exit']===124 && $process['timed_out']===true, 'bounded process terminates on timeout');

echo "PASS: {$tests} remote inventory tests\n";
