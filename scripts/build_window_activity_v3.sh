#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
if [ ! -x "${PYTHON_BIN}" ]; then
  PYTHON_BIN="python3"
fi

RUN_DIR=""
WINDOW_SECONDS="30"
TIME_BIN_SECONDS="2"
TRACEE_LOG=""
REQUEST_EVENTS=""
RUN_META=""
COLLECTION_SUMMARY=""
WINDOWS_DIR=""
OUTPUT=""
SUMMARY_OUTPUT=""
CONFIG=""
ALLOW_MISSING_TRACEE=0
ALLOW_MISSING_REQUEST_EVENTS=0
FORCE=0

usage() {
  cat <<'EOF'
Usage: scripts/build_window_activity_v3.sh --run-dir <path> [options]

Options:
  --run-dir <path>                    Run directory.
  --window-seconds <int>              Window size. Default: 30.
  --time-bin-seconds <int>            Time bin size recorded in summary. Default: 2.
  --trace-log <path>                  Trace log path. Default: <run-dir>/trace.log.
  --request-events <path>             Request events JSONL. Default: <run-dir>/request_events.jsonl.
  --run-meta <path>                   Run metadata. Default: <run-dir>/run_meta.json.
  --collection-summary <path>         Collection summary. Default: <run-dir>/collection_summary.json.
  --windows-dir <path>                Optional persisted window graph directory.
  --output <path>                     Output JSONL. Default: <run-dir>/window_activity.jsonl.
  --summary-output <path>             Summary JSON. Default: <run-dir>/window_activity_summary.json.
  --config <path>                     Optional classification policy config.
  --allow-missing-trace               Allow missing or empty trace.log.
  --allow-missing-request-events      Allow missing or empty request_events.jsonl.
  --force                            Overwrite existing window_activity.jsonl.
  -h, --help                          Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --run-dir)
      RUN_DIR="${2:?missing value for --run-dir}"
      shift 2
      ;;
    --window-seconds)
      WINDOW_SECONDS="${2:?missing value for --window-seconds}"
      shift 2
      ;;
    --time-bin-seconds)
      TIME_BIN_SECONDS="${2:?missing value for --time-bin-seconds}"
      shift 2
      ;;
    --trace-log)
      TRACEE_LOG="${2:?missing value for --trace-log}"
      shift 2
      ;;
    --request-events)
      REQUEST_EVENTS="${2:?missing value for --request-events}"
      shift 2
      ;;
    --run-meta)
      RUN_META="${2:?missing value for --run-meta}"
      shift 2
      ;;
    --collection-summary)
      COLLECTION_SUMMARY="${2:?missing value for --collection-summary}"
      shift 2
      ;;
    --windows-dir)
      WINDOWS_DIR="${2:?missing value for --windows-dir}"
      shift 2
      ;;
    --output)
      OUTPUT="${2:?missing value for --output}"
      shift 2
      ;;
    --summary-output)
      SUMMARY_OUTPUT="${2:?missing value for --summary-output}"
      shift 2
      ;;
    --config)
      CONFIG="${2:?missing value for --config}"
      shift 2
      ;;
    --allow-missing-trace)
      ALLOW_MISSING_TRACEE=1
      shift
      ;;
    --allow-missing-request-events)
      ALLOW_MISSING_REQUEST_EVENTS=1
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "${RUN_DIR}" ]; then
  echo "ERROR: --run-dir is required" >&2
  usage >&2
  exit 2
fi

BUILDER_ARGS=(
  --run-dir "${RUN_DIR}"
  --window-seconds "${WINDOW_SECONDS}"
  --time-bin-seconds "${TIME_BIN_SECONDS}"
)

[ -n "${TRACEE_LOG}" ] && BUILDER_ARGS+=(--trace-log "${TRACEE_LOG}")
[ -n "${REQUEST_EVENTS}" ] && BUILDER_ARGS+=(--request-events "${REQUEST_EVENTS}")
[ -n "${RUN_META}" ] && BUILDER_ARGS+=(--run-meta "${RUN_META}")
[ -n "${COLLECTION_SUMMARY}" ] && BUILDER_ARGS+=(--collection-summary "${COLLECTION_SUMMARY}")
[ -n "${WINDOWS_DIR}" ] && BUILDER_ARGS+=(--windows-dir "${WINDOWS_DIR}")
[ -n "${OUTPUT}" ] && BUILDER_ARGS+=(--output "${OUTPUT}")
[ -n "${SUMMARY_OUTPUT}" ] && BUILDER_ARGS+=(--summary-output "${SUMMARY_OUTPUT}")
[ -n "${CONFIG}" ] && BUILDER_ARGS+=(--config "${CONFIG}")
[ "${ALLOW_MISSING_TRACEE}" -eq 1 ] && BUILDER_ARGS+=(--allow-missing-trace)
[ "${ALLOW_MISSING_REQUEST_EVENTS}" -eq 1 ] && BUILDER_ARGS+=(--allow-missing-request-events)
[ "${FORCE}" -eq 1 ] && BUILDER_ARGS+=(--force)

echo "building window activity: ${RUN_DIR}"
"${PYTHON_BIN}" -m src.process.window_activity_builder "${BUILDER_ARGS[@]}"

CHECK_ARGS=(--run-dir "${RUN_DIR}")
[ -n "${OUTPUT}" ] && CHECK_ARGS+=(--activity "${OUTPUT}")
[ -n "${SUMMARY_OUTPUT}" ] && CHECK_ARGS+=(--summary "${SUMMARY_OUTPUT}")

echo "checking window activity: ${RUN_DIR}"
"${PYTHON_BIN}" scripts/check_window_activity_v3.py "${CHECK_ARGS[@]}"
