#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo -e "\033[1;36mStarting CTVLMS Environment...\033[0m"

if [[ ! -f config/config.php ]]; then
    echo "[!] Missing config/config.php"
    echo "    Copy config/config.example.php to config/config.php and configure the database first."
    exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
    echo "[*] Starting MariaDB service (may ask for sudo password)..."
    sudo systemctl start mariadb || true
fi

for port in 8000 8080; do
    if command -v ss >/dev/null 2>&1 && ss -ltn "sport = :$port" | grep -q LISTEN; then
        echo "[!] Port $port is already in use. Refusing to kill an unrelated process."
        exit 1
    fi
done

echo "[*] Starting CTVLMS Web Portal on 127.0.0.1:8000..."
php -S 127.0.0.1:8000 -t "$ROOT_DIR" > /tmp/ctvlms-web.log 2>&1 &
PORTAL_PID=$!

echo "[*] Starting local database/schema tools on 127.0.0.1:8080..."
php -S 127.0.0.1:8080 -t "$ROOT_DIR" > /tmp/ctvlms-tools.log 2>&1 &
TOOLS_PID=$!

cleanup() {
    echo -e "\n\033[1;31mStopping CTVLMS servers...\033[0m"
    kill "$PORTAL_PID" "$TOOLS_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo ""
echo -e "\033[1;32mCTVLMS is running locally.\033[0m"
echo "--------------------------------------------------------"
echo "Web Portal:          http://127.0.0.1:8000"
echo "Interactive Schema:  http://127.0.0.1:8080/schema_viewer.html"
echo "Database Adminer:    http://127.0.0.1:8080/adminer.php"
echo "--------------------------------------------------------"
echo "Development seed login: admin@ctvlms.local / Admin@123"
echo "Replace all seeded credentials before shared deployment."
echo ""
echo "Press Ctrl+C to stop."

wait
