#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

rm -f data/raw/realtime_tracee.log || true

rm -rf \
  data/processed/realtime_debug \
  data/processed/realtime_windows \
  data/processed/selfcheck_debug \
  data/processed/selfcheck_windows \
  data/processed/debug_test \
  data/processed/debug_test2 \
  data/processed/debug_with_bbk_attackgraph || true

echo "cleanup done"

