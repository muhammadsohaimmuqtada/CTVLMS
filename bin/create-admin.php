#!/usr/bin/env php
<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';

function hiddenPrompt(string $prompt): string
{
    fwrite(STDOUT, $prompt);
    $restore = false;
    if (PHP_OS_FAMILY !== 'Windows' && function_exists('shell_exec')) {
        @shell_exec('stty -echo');
        $restore = true;
    }
    $value = trim((string)fgets(STDIN));
    if ($restore) { @shell_exec('stty echo'); fwrite(STDOUT, PHP_EOL); }
    return $value;
}

$email = trim((string)($argv[1] ?? ''));
$name = trim((string)($argv[2] ?? 'CTVLMS Administrator'));
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    fwrite(STDERR, "Usage: php bin/create-admin.php <email> [full-name]\n");
    exit(2);
}
$password = hiddenPrompt('Admin password (minimum 12 characters): ');
$confirm = hiddenPrompt('Confirm password: ');
if (strlen($password) < 12) { fwrite(STDERR, "Password must be at least 12 characters.\n"); exit(2); }
if (!hash_equals($password, $confirm)) { fwrite(STDERR, "Passwords do not match.\n"); exit(2); }

$db = getDB();
$exists = $db->prepare('SELECT 1 FROM users WHERE email = :email');
$exists->execute([':email' => $email]);
if ($exists->fetchColumn()) { fwrite(STDERR, "A user with that email already exists.\n"); exit(1); }
$stmt = $db->prepare("INSERT INTO users (fullName, email, passwordHash, role, isActive) VALUES (:name, :email, :hash, 'Admin', 1)");
$stmt->execute([':name'=>$name, ':email'=>$email, ':hash'=>password_hash($password, PASSWORD_DEFAULT)]);
echo "Created Admin account: {$email}\n";
