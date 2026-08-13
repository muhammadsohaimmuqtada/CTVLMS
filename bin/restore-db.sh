#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 ]]; then
  echo "Usage: CTVLMS_RESTORE_CONFIRM=YES $0 /path/to/ctvlms-YYYYmmddTHHMMSSZ.sql.gz" >&2
  exit 2
fi
[[ "${CTVLMS_RESTORE_CONFIRM:-}" == "YES" ]] || {
  echo "Refusing restore without CTVLMS_RESTORE_CONFIRM=YES" >&2
  exit 2
}

ENV_FILE="${CTVLMS_ENV_FILE:-/etc/ctvlms/ctvlms.env}"
backup="$1"
[[ -r "$backup" ]] || { echo "Backup is not readable: $backup" >&2; exit 2; }
[[ "$backup" == *.sql.gz ]] || { echo "Expected a .sql.gz backup" >&2; exit 2; }

if [[ -r "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

: "${CTVLMS_DB_HOST:?CTVLMS_DB_HOST is required}"
: "${CTVLMS_DB_PORT:?CTVLMS_DB_PORT is required}"
: "${CTVLMS_DB_USER:?CTVLMS_DB_USER is required}"
: "${CTVLMS_DB_PASSWORD:?CTVLMS_DB_PASSWORD is required}"

command -v mariadb >/dev/null || { echo "mariadb is required" >&2; exit 1; }
command -v gzip >/dev/null || { echo "gzip is required" >&2; exit 1; }

gzip -t "$backup"
if [[ -r "${backup}.sha256" ]]; then
  (cd "$(dirname "$backup")" && sha256sum -c "$(basename "${backup}.sha256")")
fi

printf 'Restoring %s to %s:%s as %s\n' "$backup" "$CTVLMS_DB_HOST" "$CTVLMS_DB_PORT" "$CTVLMS_DB_USER" >&2
gzip -dc "$backup" | MYSQL_PWD="$CTVLMS_DB_PASSWORD" mariadb \
  --host="$CTVLMS_DB_HOST" \
  --port="$CTVLMS_DB_PORT" \
  --user="$CTVLMS_DB_USER"

echo "Restore completed. Run php bin/production-check.php and the test suite before returning the service to traffic." >&2
