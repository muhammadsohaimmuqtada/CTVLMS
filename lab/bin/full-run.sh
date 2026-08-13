#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB="$ROOT/lab"
KEEP="${CTVLMS_LAB_KEEP:-0}"

cleanup() {
  if [[ "$KEEP" != 1 ]]; then
    bash "$LAB/bin/down.sh" >/dev/null 2>&1 || true
  else
    echo "CTVLMS_LAB_KEEP=1: disposable lab left running for inspection."
  fi
}
trap cleanup EXIT

cd "$ROOT"
bash "$LAB/bin/up.sh"
# shellcheck disable=SC1091
source "$LAB/.state/env.sh"
php "$LAB/bin/bootstrap.php"
php "$LAB/bin/run-acceptance.php"
bash "$LAB/bin/backup-restore-drill.sh"

echo "CTVLMS pilot release-candidate lab: PASS"
