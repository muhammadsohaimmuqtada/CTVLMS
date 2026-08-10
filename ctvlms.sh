#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
PORT="${CTVLMS_PORT:-8000}"

echo -e "\033[1;36mStarting CTVLMS...\033[0m"
if [[ ! -f config/config.php ]]; then
  echo "[!] Missing config/config.php"
  echo "    cp config/config.example.php config/config.php"
  exit 1
fi
for ext in pdo_mysql SimpleXML; do
  php -m | grep -Fxqi "$ext" || { echo "[!] Missing PHP extension: $ext"; exit 1; }
done
command -v nmap >/dev/null || { echo "[!] nmap is required"; exit 1; }
if command -v ss >/dev/null 2>&1 && ss -ltn "sport = :$PORT" | grep -q LISTEN; then
  echo "[!] Port $PORT is already in use."
  exit 1
fi
php -r 'require "config/config.php"; require "config/database.php"; getDB()->query("SELECT 1"); echo "[*] Database connection: OK\n";' || {
  echo "[!] Database connection failed. Start/configure MariaDB first."
  exit 1
}

echo "[*] Web portal: http://127.0.0.1:${PORT}"
php -S "127.0.0.1:${PORT}" "$ROOT_DIR/router.php" > /tmp/ctvlms-web.log 2>&1 &
PORTAL_PID=$!
cleanup() { kill "$PORTAL_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
wait "$PORTAL_PID"
