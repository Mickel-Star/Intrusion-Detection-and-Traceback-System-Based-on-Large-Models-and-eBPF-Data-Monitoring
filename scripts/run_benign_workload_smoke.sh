#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
if [ ! -x "${PYTHON_BIN}" ]; then
  PYTHON_BIN="python3"
fi

CONFIG_PATH="${CONFIG_PATH:-configs/benign_corpus_v3.yaml}"
OUTPUT_DIR="${OUTPUT_DIR:-data/benign_corpus_v3/smoke/run_smoke}"
BASE_URL="${BASE_URL:-}"

DRIVER_ARGS=(--config "${CONFIG_PATH}" --output-dir "${OUTPUT_DIR}")
if [ -n "${BASE_URL}" ]; then
  DRIVER_ARGS+=(--base-url "${BASE_URL}")
fi

"${PYTHON_BIN}" -m src.process.benign_workload_driver "${DRIVER_ARGS[@]}"

for required in run_meta.json driver.log request_events.jsonl workload_summary.json; do
  if [ ! -f "${OUTPUT_DIR}/${required}" ]; then
    echo "missing required output: ${OUTPUT_DIR}/${required}" >&2
    exit 1
  fi
done

"${PYTHON_BIN}" - "${OUTPUT_DIR}/request_events.jsonl" <<'PY'
import json
import sys
from pathlib import Path

events_path = Path(sys.argv[1])
required_actors = {"foreground_user", "readonly_user", "background_worker"}
seen_actors = set()
violations = []

with events_path.open("r", encoding="utf-8") as fp:
    for line_no, line in enumerate(fp, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid jsonl at line {line_no}: {exc}") from exc
        actor = str(event.get("actor") or "")
        profile = str(event.get("profile") or "")
        action = str(event.get("action") or "")
        state_before = str(event.get("state_before") or "")
        seen_actors.add(actor)

        if profile == "catalog_browse_search" and action in {"catalog", "search", "item_detail", "order_read"}:
            if state_before == "anonymous":
                violations.append((line_no, "catalog_browse_search before login", event))
        if profile == "order_write_checkout" and action == "order_checkout":
            if state_before != "item_selected":
                violations.append((line_no, "order_write_checkout before item_selected", event))
        if profile == "admin_readonly_audit" and action in {"admin_audit", "admin_inspection", "report_status"}:
            if state_before != "admin_login_success":
                violations.append((line_no, "admin_readonly_audit before admin login", event))

missing = sorted(required_actors - seen_actors)
if missing:
    raise SystemExit(f"missing actor records: {missing}")
if violations:
    sample = violations[0]
    raise SystemExit(f"state machine validation failed at line {sample[0]}: {sample[1]} {json.dumps(sample[2], sort_keys=True)}")

print(f"smoke validation ok: actors={sorted(seen_actors)} events_file={events_path}")
PY

echo "benign workload smoke outputs: ${OUTPUT_DIR}"
