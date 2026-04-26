#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

today="$(date +%F)"

delete_non_today_under() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  while IFS= read -r -d '' f; do
    rm -f "$f" || true
  done < <(find "$dir" -type f ! -newermt "$today" -print0)
}

delete_non_today_under "data/raw"
delete_non_today_under "data/processed"

rm -rf data/processed/debug data/processed/windows 2>/dev/null || true

echo "cleanup done (kept only files modified on ${today})"

