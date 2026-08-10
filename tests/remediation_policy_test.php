<?php
require_once __DIR__ . '/../includes/remediation.php';
$tests = 0;
function rcheck(bool $ok, string $msg): void { global $tests; $tests++; if (!$ok) { fwrite(STDERR,"FAIL: {$msg}\n"); exit(1); } }
foreach (['apache2','libssl3:amd64','python3.13-minimal','libstdc++6'] as $name) rcheck(validatePackageName($name) === $name, "valid package {$name}");
foreach (['','--allow-unauthenticated','-y','bad package','$(id)','a;id'] as $name) {
    $rejected = false; try { validatePackageName($name); } catch (RuntimeException) { $rejected = true; }
    rcheck($rejected, "reject unsafe package {$name}");
}
[$query,$upgrade] = packageCommands('apt','apache2');
rcheck(str_contains($query,'apache2') && str_contains($upgrade,'--only-upgrade'), 'apt fixed command policy');
$unsupported = false; try { packageCommands('brew','openssl'); } catch (RuntimeException) { $unsupported = true; }
rcheck($unsupported, 'unsupported manager rejected');
echo "PASS: {$tests} remediation policy tests\n";
