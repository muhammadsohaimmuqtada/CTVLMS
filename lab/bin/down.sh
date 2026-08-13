#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB="$ROOT/lab"
docker compose -f "$LAB/docker-compose.yml" down -v --remove-orphans
rm -rf "$LAB/.state"
