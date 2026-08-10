<?php
/** Pure remediation command policy. No DB or network side effects. */
function validatePackageName(string $package): string
{
    $package = trim($package);
    if ($package === '' || strlen($package) > 200 || !preg_match('/^[A-Za-z0-9][A-Za-z0-9.+:_-]*$/', $package)) {
        throw new RuntimeException('Package name failed validation.');
    }
    return $package;
}

function packageCommands(string $manager, string $package): array
{
    $package = validatePackageName($package);
    return match ($manager) {
        'apt' => [
            "dpkg-query -W -f='\${Version}' {$package}",
            "sudo -n apt-get update && sudo -n apt-get install --only-upgrade -y {$package}",
        ],
        'dnf' => [
            "rpm -q --qf '%{VERSION}-%{RELEASE}' {$package}",
            "sudo -n dnf -y upgrade {$package}",
        ],
        'yum' => [
            "rpm -q --qf '%{VERSION}-%{RELEASE}' {$package}",
            "sudo -n yum -y update {$package}",
        ],
        'apk' => [
            "apk info -v {$package} | head -n 1",
            "sudo -n apk upgrade {$package}",
        ],
        default => throw new RuntimeException('Unsupported package manager.'),
    };
}
