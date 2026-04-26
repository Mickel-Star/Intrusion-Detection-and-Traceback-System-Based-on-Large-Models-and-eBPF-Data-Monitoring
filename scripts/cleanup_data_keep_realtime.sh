#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

keep() {
  local p="$1"
  if [ -e "$p" ]; then
    echo "$p"
  fi
}

keep_list=()
keep_list+=("$(keep data/kb)")
keep_list+=("$(keep data/bbk.sqlite)")
keep_list+=("$(keep data/models)")
keep_list+=("$(keep data/vector_db)")

tmp_dir="$(mktemp -d)"
for p in "${keep_list[@]}"; do
  [ -n "$p" ] || continue
  cp -a "$p" "$tmp_dir/" 2>/dev/null || true
done

rm -rf data
mkdir -p data/raw data/processed

for p in "$tmp_dir"/*; do
  base="$(basename "$p")"
  cp -a "$p" "data/${base}" 2>/dev/null || true
done

rm -rf "$tmp_dir"

echo "cleanup done (kept kb, models)"
