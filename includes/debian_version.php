<?php
/** Debian version ordering backed by dpkg's authoritative implementation. */

function runDpkgVersionPredicate(string $left, string $operator, string $right): bool
{
    foreach ([$left, $right] as $version) {
        if ($version === '' || strlen($version) > 255 || str_contains($version, "\0") || str_contains($version, "\n")) {
            throw new InvalidArgumentException('Invalid Debian package version.');
        }
    }
    if (!in_array($operator, ['lt', 'eq', 'gt'], true)) {
        throw new InvalidArgumentException('Invalid dpkg comparison operator.');
    }
    $dpkg = '/usr/bin/dpkg';
    if (!is_executable($dpkg)) throw new RuntimeException('dpkg is required for Debian version comparison.');

    $descriptor = [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']];
    $process = proc_open([$dpkg, '--compare-versions', $left, $operator, $right], $descriptor, $pipes);
    if (!is_resource($process)) throw new RuntimeException('Unable to launch dpkg version comparison.');
    fclose($pipes[0]);
    stream_get_contents($pipes[1]);
    $stderr = trim((string)stream_get_contents($pipes[2]));
    fclose($pipes[1]); fclose($pipes[2]);
    $exit = proc_close($process);
    if ($exit === 0) return true;
    if ($exit === 1) return false;
    throw new RuntimeException('dpkg version comparison failed' . ($stderr !== '' ? ': ' . $stderr : '.'));
}

function debianVersionCompare(string $left, string $right): int
{
    if (runDpkgVersionPredicate($left, 'eq', $right)) return 0;
    return runDpkgVersionPredicate($left, 'lt', $right) ? -1 : 1;
}
