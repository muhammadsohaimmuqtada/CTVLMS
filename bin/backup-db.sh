#!/usr/bin/env bash
set -euo pipefail
umask 077

ENV_FILE="${CTVLMS_ENV_FILE:-/etc/ctvlms/ctvlms.env}"
BACKUP_DIR="${CTVLMS_BACKUP_DIR:-/var/backups/ctvlms}"
RETENTION_DAYS="${CTVLMS_BACKUP_RETENTION_DAYS:-14}"

if [[ -r "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

: "${CTVLMS_DB_HOST:?CTVLMS_DB_HOST is required}"
: "${CTVLMS_DB_PORT:?CTVLMS_DB_PORT is required}"
: "${CTVLMS_DB_NAME:?CTVLMS_DB_NAME is required}"
: "${CTVLMS_DB_USER:?CTVLMS_DB_USER is required}"
: "${CTVLMS_DB_PASSWORD:?CTVLMS_DB_PASSWORD is required}"

[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || { echo "Invalid retention days" >&2; exit 2; }
command -v mariadb-dump >/dev/null || { echo "mariadb-dump is required" >&2; exit 1; }
command -v gzip >/dev/null || { echo "gzip is required" >&2; exit 1; }

install -d -m 0700 "$BACKUP_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
final="$BACKUP_DIR/ctvlms-${stamp}.sql.gz"
tmp="${final}.tmp"
trap 'rm -f "$tmp"' EXIT

MYSQL_PWD="$CTVLMS_DB_PASSWORD" mariadb-dump \
  --host="$CTVLMS_DB_HOST" \
  --port="$CTVLMS_DB_PORT" \
  --user="$CTVLMS_DB_USER" \
  --single-transaction \
  --quick \
  --routines \
  --triggers \
  --events \
  --hex-blob \
  --databases "$CTVLMS_DB_NAME" \
  | gzip -9 > "$tmp"

test -s "$tmp"
gzip -t "$tmp"
mv "$tmp" "$final"
sha256sum "$final" > "${final}.sha256"
chmod 0600 "$final" "${final}.sha256"

find "$BACKUP_DIR" -type f \( -name 'ctvlms-*.sql.gz' -o -name 'ctvlms-*.sql.gz.sha256' \) \
  -mtime "+$RETENTION_DAYS" -delete

printf '%s\n' "$final"
