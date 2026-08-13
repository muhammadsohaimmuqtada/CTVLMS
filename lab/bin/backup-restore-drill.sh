#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB="$ROOT/lab"
STATE="$LAB/.state"

[[ -r "$STATE/env.sh" ]] || { echo "Run lab/bin/up.sh first" >&2; exit 1; }
# shellcheck disable=SC1091
source "$STATE/env.sh"
[[ "${CTVLMS_LAB_MODE:-}" == 1 && "${CTVLMS_DB_PORT:-}" == 33306 ]] || {
  echo "Refusing backup/restore drill outside isolated pilot DB" >&2
  exit 1
}

export CTVLMS_BACKUP_DIR="$STATE/backups"
export CTVLMS_DB_USER=root
export CTVLMS_DB_PASSWORD="$CTVLMS_LAB_DB_ROOT_PASSWORD"
backup="$(bash "$ROOT/bin/backup-db.sh")"
[[ -s "$backup" && -s "${backup}.sha256" ]]

original="$(MYSQL_PWD="$CTVLMS_DB_PASSWORD" mariadb -N -B -h "$CTVLMS_DB_HOST" -P "$CTVLMS_DB_PORT" -u root ctvlms \
  -e "SELECT assetName FROM assets WHERE ipAddress='172.28.77.11' LIMIT 1")"
[[ "$original" == 'ctvlms-lab-canary' ]] || { echo "Unexpected lab marker before restore drill" >&2; exit 1; }

MYSQL_PWD="$CTVLMS_DB_PASSWORD" mariadb -h "$CTVLMS_DB_HOST" -P "$CTVLMS_DB_PORT" -u root ctvlms \
  -e "UPDATE assets SET assetName='ctvlms-lab-mutated-after-backup' WHERE ipAddress='172.28.77.11'"
mutated="$(MYSQL_PWD="$CTVLMS_DB_PASSWORD" mariadb -N -B -h "$CTVLMS_DB_HOST" -P "$CTVLMS_DB_PORT" -u root ctvlms \
  -e "SELECT assetName FROM assets WHERE ipAddress='172.28.77.11' LIMIT 1")"
[[ "$mutated" == 'ctvlms-lab-mutated-after-backup' ]]

CTVLMS_RESTORE_CONFIRM=YES bash "$ROOT/bin/restore-db.sh" "$backup"
restored="$(MYSQL_PWD="$CTVLMS_DB_PASSWORD" mariadb -N -B -h "$CTVLMS_DB_HOST" -P "$CTVLMS_DB_PORT" -u root ctvlms \
  -e "SELECT assetName FROM assets WHERE ipAddress='172.28.77.11' LIMIT 1")"
[[ "$restored" == 'ctvlms-lab-canary' ]] || {
  echo "Restore drill failed: expected ctvlms-lab-canary, got $restored" >&2
  exit 1
}

echo "PASS: backup checksum, mutation, destructive restore, and restored-state verification"
