#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
if [ ! -x "${PYTHON_BIN}" ]; then
  PYTHON_BIN="python3"
fi

CORPUS_DIR=""
WINDOW_SECONDS="30"
TIME_BIN_SECONDS="2"
SEED="20260501"
SAMPLING_CONFIG=""
OUTPUT_MANIFEST=""
OUTPUT_SUMMARY=""
OUTPUT_FULL_INDEX=""
OUTPUT_SAMPLED_TRAIN=""
INCLUDE_SPLITS=""
FORCE=0
STRICT=0
ALLOW_MISSING_RUNS=0

usage() {
  cat <<'EOF'
Usage: scripts/build_benign_manifest_v3.sh --corpus-dir <path> [options]

Options:
  --corpus-dir <path>             Benign corpus root directory.
  --window-seconds <int>          Window size. Default: 30.
  --time-bin-seconds <int>        Time bin size. Default: 2.
  --seed <int>                    Sampling seed. Default: 20260501.
  --sampling-config <path>        Sampling policy config. Default: configs/benign_manifest_v3.yaml.
  --output-manifest <path>        Output corpus_manifest.json.
  --output-summary <path>         Output corpus_summary.json.
  --output-full-index <path>      Output full_window_index.jsonl.
  --output-sampled-train <path>   Output sampled_train_windows.jsonl.
  --include-splits <list>         Comma-separated split names. Default: train,calibration,holdout.
  --force                         Overwrite existing manifest outputs.
  --strict                        Fail on missing run metadata/activity files and split collisions.
  --allow-missing-runs            Allow missing configured run dirs with warnings.
  -h, --help                      Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --corpus-dir)
      CORPUS_DIR="${2:?missing value for --corpus-dir}"
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
    --seed)
      SEED="${2:?missing value for --seed}"
      shift 2
      ;;
    --sampling-config)
      SAMPLING_CONFIG="${2:?missing value for --sampling-config}"
      shift 2
      ;;
    --output-manifest)
      OUTPUT_MANIFEST="${2:?missing value for --output-manifest}"
      shift 2
      ;;
    --output-summary)
      OUTPUT_SUMMARY="${2:?missing value for --output-summary}"
      shift 2
      ;;
    --output-full-index)
      OUTPUT_FULL_INDEX="${2:?missing value for --output-full-index}"
      shift 2
      ;;
    --output-sampled-train)
      OUTPUT_SAMPLED_TRAIN="${2:?missing value for --output-sampled-train}"
      shift 2
      ;;
    --include-splits)
      INCLUDE_SPLITS="${2:?missing value for --include-splits}"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --strict)
      STRICT=1
      shift
      ;;
    --allow-missing-runs)
      ALLOW_MISSING_RUNS=1
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

if [ -z "${CORPUS_DIR}" ]; then
  echo "ERROR: --corpus-dir is required" >&2
  usage >&2
  exit 2
fi

BUILDER_ARGS=(
  --corpus-dir "${CORPUS_DIR}"
  --window-seconds "${WINDOW_SECONDS}"
  --time-bin-seconds "${TIME_BIN_SECONDS}"
  --seed "${SEED}"
)

[ -n "${SAMPLING_CONFIG}" ] && BUILDER_ARGS+=(--sampling-config "${SAMPLING_CONFIG}")
[ -n "${OUTPUT_MANIFEST}" ] && BUILDER_ARGS+=(--output-manifest "${OUTPUT_MANIFEST}")
[ -n "${OUTPUT_SUMMARY}" ] && BUILDER_ARGS+=(--output-summary "${OUTPUT_SUMMARY}")
[ -n "${OUTPUT_FULL_INDEX}" ] && BUILDER_ARGS+=(--output-full-index "${OUTPUT_FULL_INDEX}")
[ -n "${OUTPUT_SAMPLED_TRAIN}" ] && BUILDER_ARGS+=(--output-sampled-train "${OUTPUT_SAMPLED_TRAIN}")
[ -n "${INCLUDE_SPLITS}" ] && BUILDER_ARGS+=(--include-splits "${INCLUDE_SPLITS}")
[ "${FORCE}" -eq 1 ] && BUILDER_ARGS+=(--force)
[ "${STRICT}" -eq 1 ] && BUILDER_ARGS+=(--strict)
[ "${ALLOW_MISSING_RUNS}" -eq 1 ] && BUILDER_ARGS+=(--allow-missing-runs)

echo "building benign corpus manifest: ${CORPUS_DIR}"
"${PYTHON_BIN}" -m src.process.benign_manifest_builder "${BUILDER_ARGS[@]}"

CHECK_ARGS=(--corpus-dir "${CORPUS_DIR}")
[ "${STRICT}" -eq 1 ] && CHECK_ARGS+=(--strict)

echo "checking benign corpus manifest: ${CORPUS_DIR}"
"${PYTHON_BIN}" scripts/check_benign_manifest_v3.py "${CHECK_ARGS[@]}"
