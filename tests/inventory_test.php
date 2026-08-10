<?php
require_once __DIR__ . '/../includes/inventory.php';
$tests = 0;
function t(bool $ok, string $msg): void { global $tests; $tests++; if (!$ok) { fwrite(STDERR, "FAIL: $msg\n"); exit(1); } }
$os = parseOsReleaseText("ID=kali\nPRETTY_NAME=\"Kali GNU/Linux Rolling\"\nVERSION_ID=\"2026.3\"\n");
t($os['ID'] === 'kali', 'os-release ID');
t($os['PRETTY_NAME'] === 'Kali GNU/Linux Rolling', 'os-release quoted value');
$cpes = platformCpesForFacts(['os_family'=>'linux']);
t(count($cpes) === 1 && str_contains($cpes[0], ':linux:linux_kernel:'), 'Linux platform CPE');
$pkgs = parseDpkgInventory("apache2\t2.4.68-1\tamd64\npython3\t3.13.14-1\tamd64\nmalformed\n");
t(count($pkgs) === 2, 'dpkg parser count');
t($pkgs[0]['package'] === 'apache2' && $pkgs[1]['version'] === '3.13.14-1', 'dpkg parser values');
echo "PASS: {$tests} inventory tests\n";
