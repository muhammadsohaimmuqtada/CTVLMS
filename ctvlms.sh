#!/bin/bash

echo -e "\033[1;36mStarting CTVLMS Environment...\033[0m"

# 1. Start MariaDB
echo "[*] Starting MariaDB service (may ask for sudo password)..."
sudo systemctl start mariadb

# 2. Kill any existing PHP servers on these ports to avoid "address already in use" errors
echo "[*] Cleaning up old server instances..."
fuser -k 8000/tcp 2>/dev/null
fuser -k 8080/tcp 2>/dev/null

# 3. Start CTVLMS portal
echo "[*] Starting CTVLMS Web Portal on port 8000..."
cd /home/kali/Downloads/Tools/ctvlms
php -S localhost:8000 > /dev/null 2>&1 &
PORTAL_PID=$!

# 4. Start Schema/Adminer server
echo "[*] Starting Database Tools on port 8080..."
php -S localhost:8080 > /dev/null 2>&1 &
TOOLS_PID=$!

echo ""
echo -e "\033[1;32m✅ CTVLMS is now LIVE!\033[0m"
echo -e "--------------------------------------------------------"
echo -e "\033[1;34m🌍 Web Portal:\033[0m          http://localhost:8000"
echo -e "\033[1;34m📊 Interactive Schema:\033[0m  http://localhost:8080/schema_viewer.html"
echo -e "\033[1;34m🗄️  Database Adminer:\033[0m    http://localhost:8080/adminer.php"
echo -e "--------------------------------------------------------"
echo -e "Default Login: \033[1madmin@ctvlms.local\033[0m / \033[1mAdmin@123\033[0m"
echo -e ""
echo -e "Servers are running in the background."
echo -e "Press \033[1;31mCtrl+C\033[0m here to stop all servers and exit."

# Wait for Ctrl+C to kill the background servers cleanly
trap "echo -e '\n\033[1;31mStopping servers...\033[0m'; kill $PORTAL_PID $TOOLS_PID 2>/dev/null; exit 0" SIGINT SIGTERM
wait
