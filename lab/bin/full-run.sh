#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB="$ROOT/lab"
STATE="$LAB/.state"
KEEP="${CTVLMS_LAB_KEEP:-0}"
CONFIG="$ROOT/config/config.php"
CONFIG_BACKUP="$STATE/config.php.before-lab"
HAD_CONFIG=0
CONFIG_SWAPPED=0

mkdir -p "$STATE"
if [[ -f "$CONFIG" ]]; then
  HAD_CONFIG=1
  cp -p "$CONFIG" "$CONFIG_BACKUP"
fi

cleanup() {
  # Only restore/remove config if this run actually swapped it. A Docker/startup
  # failure before the swap must leave the user's checkout untouched.
  if [[ "$CONFIG_SWAPPED" == 1 ]]; then
    if [[ "$HAD_CONFIG" == 1 && -f "$CONFIG_BACKUP" ]]; then
      cp -p "$CONFIG_BACKUP" "$CONFIG"
    elif [[ "$HAD_CONFIG" == 0 ]]; then
      rm -f "$CONFIG"
    fi
  fi

  if [[ "$KEEP" != 1 ]]; then
    bash "$LAB/bin/down.sh" >/dev/null 2>&1 || true
  else
    echo "CTVLMS_LAB_KEEP=1: disposable lab left running for inspection."
    echo "Lab environment remains at $STATE/env.sh; your normal config/config.php has already been restored if it was swapped."
  fi
}
trap cleanup EXIT

cd "$ROOT"
bash "$LAB/bin/up.sh"
cp "$ROOT/config/config.example.php" "$CONFIG"
CONFIG_SWAPPED=1

# shellcheck disable=SC1091
source "$STATE/env.sh"
php "$LAB/bin/bootstrap.php"
php "$LAB/bin/run-acceptance.php"
bash "$LAB/bin/backup-restore-drill.sh"

echo "CTVLMS pilot release-candidate lab: PASS"
