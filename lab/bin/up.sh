#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB="$ROOT/lab"
STATE="$LAB/.state"
COMPOSE=(docker compose -f "$LAB/docker-compose.yml")
TARGETS=(172.28.77.11 172.28.77.12 172.28.77.13 172.28.77.14)

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v ssh-keygen >/dev/null || { echo "ssh-keygen is required" >&2; exit 1; }
command -v ssh-keyscan >/dev/null || { echo "ssh-keyscan is required" >&2; exit 1; }
command -v mariadb >/dev/null || { echo "mariadb client is required" >&2; exit 1; }

mkdir -p "$STATE"
rm -f "$STATE/id_ed25519" "$STATE/id_ed25519.pub" "$STATE/known_hosts" "$STATE/env.sh"
ssh-keygen -q -t ed25519 -N '' -C 'ctvlms-pilot-lab' -f "$STATE/id_ed25519"
chmod 0600 "$STATE/id_ed25519"
chmod 0644 "$STATE/id_ed25519.pub"

# This project name is fixed in compose, so cleanup is scoped to the disposable
# pilot lab and cannot affect the normal CTVLMS database/container.
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --build

for _ in $(seq 1 60); do
  if MYSQL_PWD='ctvlms-lab-root-2026' mariadb-admin \
      -h 127.0.0.1 -P 33306 -u root ping --silent >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
MYSQL_PWD='ctvlms-lab-root-2026' mariadb-admin \
  -h 127.0.0.1 -P 33306 -u root ping --silent >/dev/null

MYSQL_PWD='ctvlms-lab-root-2026' mariadb -h 127.0.0.1 -P 33306 -u root < "$ROOT/database/schema.sql"
for migration in "$ROOT"/database/migrations/*.sql; do
  MYSQL_PWD='ctvlms-lab-root-2026' mariadb -h 127.0.0.1 -P 33306 -u root ctvlms < "$migration"
done

: > "$STATE/known_hosts"
for ip in "${TARGETS[@]}"; do
  found=''
  for _ in $(seq 1 40); do
    found="$(ssh-keyscan -T 2 "$ip" 2>/dev/null || true)"
    [[ -n "$found" ]] && break
    sleep 1
  done
  [[ -n "$found" ]] || {
    echo "Unable to reach disposable SSH target $ip. Rootless/custom Docker networking may not expose bridge IPs to the host." >&2
    exit 1
  }
  printf '%s\n' "$found" >> "$STATE/known_hosts"
done
chmod 0600 "$STATE/known_hosts"

cat > "$STATE/env.sh" <<EOF
export CTVLMS_LAB_MODE=1
export CTVLMS_DB_HOST=127.0.0.1
export CTVLMS_DB_PORT=33306
export CTVLMS_DB_NAME=ctvlms
export CTVLMS_DB_USER=ctvlms_lab_app
export CTVLMS_DB_PASSWORD=ctvlms-lab-app-password-2026
export CTVLMS_LAB_DB_ROOT_PASSWORD=ctvlms-lab-root-2026
export CTVLMS_LAB_SSH_KEY=$STATE/id_ed25519
export CTVLMS_LAB_KNOWN_HOSTS=$STATE/known_hosts
export CTVLMS_EXECUTE_PATCHES=1
export CTVLMS_MAX_PATCHES_PER_CYCLE=1
export CTVLMS_PATCH_LEASE_SECONDS=60
export CTVLMS_WORKER_ID=ctvlms-pilot-lab-worker
EOF
chmod 0600 "$STATE/env.sh"

printf 'Pilot lab is up. Environment: %s\n' "$STATE/env.sh"
printf 'Next: source %q && php %q\n' "$STATE/env.sh" "$LAB/bin/bootstrap.php"
