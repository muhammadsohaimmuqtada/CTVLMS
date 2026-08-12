<?php
/** Strict, non-interactive SSH transport for fixed inventory probes. */
require_once __DIR__ . '/process.php';

function sshUserIsValid(string $user): bool
{
    return $user !== '' && strlen($user) <= 100 && !str_starts_with($user, '-') &&
        preg_match('/^[A-Za-z0-9._-]+$/', $user) === 1;
}

function sshEnvReferenceIsValid(string $name): bool
{
    return preg_match('/^[A-Z_][A-Z0-9_]*$/', $name) === 1;
}

function requiredFileFromEnv(string $envName, string $label): string
{
    if (!sshEnvReferenceIsValid($envName)) throw new RuntimeException("{$label} environment reference is invalid.");
    $path = trim((string)getenv($envName));
    if ($path === '' || !is_file($path) || !is_readable($path)) {
        throw new RuntimeException("{$label} file referenced by {$envName} is unavailable or unreadable.");
    }
    return $path;
}

function buildStrictSshArgv(
    string $ip,
    string $user,
    string $privateKeyPath,
    string $knownHostsPath,
    string $remoteCommand,
    int $connectTimeoutSeconds = 10
): array {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) throw new InvalidArgumentException('SSH target must be a valid IP address.');
    if (!sshUserIsValid($user)) throw new InvalidArgumentException('Invalid SSH user.');
    if ($privateKeyPath === '' || $knownHostsPath === '') throw new InvalidArgumentException('SSH trust files are required.');
    if ($remoteCommand === '' || str_contains($remoteCommand, "\0")) throw new InvalidArgumentException('Invalid fixed remote command.');
    $connectTimeoutSeconds = max(1, min(60, $connectTimeoutSeconds));

    return [
        'ssh', '-i', $privateKeyPath,
        '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'ConnectTimeout=' . $connectTimeoutSeconds,
        '-o', 'ConnectionAttempts=1',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', 'UserKnownHostsFile=' . $knownHostsPath,
        '-o', 'ServerAliveInterval=15',
        '-o', 'ServerAliveCountMax=4',
        $user . '@' . $ip,
        $remoteCommand,
    ];
}

function inventorySshCommand(string $probe): string
{
    return match ($probe) {
        'os_release' => 'cat /etc/os-release',
        'hostname' => 'hostname',
        'architecture' => 'uname -m',
        'kernel' => 'uname -r',
        'packages' => "/usr/bin/dpkg-query -W -f='\${binary:Package}\\t\${Version}\\t\${Architecture}\\t\${source:Package}\\t\${source:Version}\\t\${source:Upstream-Version}\\n'",
        default => throw new InvalidArgumentException('Unknown inventory SSH probe.'),
    };
}

function runInventorySshProbe(array $policy, string $probe, int $timeoutSeconds = 120): array
{
    $command = inventorySshCommand($probe);
    $keyPath = requiredFileFromEnv((string)$policy['sshKeyEnv'], 'SSH private key');
    $knownHostsPath = requiredFileFromEnv((string)$policy['knownHostsEnv'], 'SSH known-hosts');
    $argv = buildStrictSshArgv(
        (string)$policy['ipAddress'], (string)$policy['sshUser'], $keyPath, $knownHostsPath, $command,
        (int)($policy['connectTimeoutSeconds'] ?? 10)
    );
    return runBoundedProcess($argv, $timeoutSeconds, $probe === 'packages' ? 134217728 : 1048576);
}
