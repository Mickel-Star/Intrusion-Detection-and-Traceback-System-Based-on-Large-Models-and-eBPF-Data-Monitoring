#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.analysis.report_generator import AnalysisEngine
from src.common.defaults import (
    DEFAULT_ALERT_THRESHOLD,
    DEFAULT_BBK_TRAIN_WINDOW_SECONDS,
    DEFAULT_BENIGN_CORPUS_DIR,
    DEFAULT_BENIGN_HOLDOUT_RUN_ID,
)
from src.common.io import read_json, write_json
from src.process.log_parser import TraceeLogParser
from src.process.streaming_reduction import StreamingReductionConfig, StreamingReducer
from src.process.window_io import dump_window_graph


def materialize_windows(trace_path: Path, windows_dir: Path, window_seconds: int) -> int:
    parser = TraceeLogParser()
    logs = parser.parse_log_file(str(trace_path))
    reducer = StreamingReducer(config=StreamingReductionConfig(window_seconds=int(window_seconds), time_bin_seconds=1))
    windows_dir.mkdir(parents=True, exist_ok=True)

    for stale in sorted(windows_dir.glob("window_*.json")):
        stale.unlink()

    count = 0
    for graph, _metas in reducer.ingest_logs(logs):
        count += 1
        dump_window_graph(str(windows_dir / f"window_{count:04d}.json"), graph)
    return count


def evaluate_holdout_run(
    *,
    corpus_dir: Path,
    run_id: str,
    threshold: float,
    window_seconds: int,
) -> dict[str, Any]:
    run_dir = corpus_dir / run_id
    trace_path = run_dir / "trace.log"
    run_meta_path = run_dir / "run_meta.json"
    if not trace_path.exists():
        raise FileNotFoundError(f"holdout trace not found: {trace_path}")
    if not run_meta_path.exists():
        raise FileNotFoundError(f"holdout run_meta not found: {run_meta_path}")

    run_meta = read_json(str(run_meta_path)) or {}
    split_role = str(run_meta.get("split_role") or "").strip().lower()
    if split_role and split_role != "holdout":
        raise ValueError(f"requested run is not marked holdout: {run_id} ({split_role})")

    windows_dir = run_dir / f"windows_{int(window_seconds):02d}s"
    total_windows = materialize_windows(trace_path, windows_dir, window_seconds=int(window_seconds))

    engine = AnalysisEngine()
    alerts = engine.detect_window_alerts_from_windows(str(windows_dir), threshold=float(threshold))
    false_positive_windows = int(len(alerts))
    duration_seconds = int(run_meta.get("duration_seconds") or (total_windows * int(window_seconds)))
    alerts_per_minute = (
        float(false_positive_windows) / max(float(duration_seconds) / 60.0, 1e-9)
        if duration_seconds > 0
        else 0.0
    )

    return {
        "schema_version": 1,
        "metric_type": "benign_holdout",
        "run_id": run_id,
        "split_role": split_role or "holdout",
        "trace_out": str(trace_path),
        "windows_dir": str(windows_dir),
        "window_seconds": int(window_seconds),
        "threshold": float(threshold),
        "duration_seconds": int(duration_seconds),
        "total_windows": int(total_windows),
        "false_positive_windows": int(false_positive_windows),
        "false_positive_rate": (
            float(false_positive_windows) / float(total_windows)
            if total_windows > 0
            else 0.0
        ),
        "alerts_per_minute": float(alerts_per_minute),
        "alert_window_ids": [str(alert.window_id) for alert in alerts],
        "alert_scores": {
            str(alert.window_id): float(alert.window_score)
            for alert in alerts
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", default=DEFAULT_BENIGN_CORPUS_DIR)
    ap.add_argument("--run-id", default=DEFAULT_BENIGN_HOLDOUT_RUN_ID)
    ap.add_argument("--threshold", type=float, default=DEFAULT_ALERT_THRESHOLD)
    ap.add_argument("--window-seconds", type=int, default=DEFAULT_BBK_TRAIN_WINDOW_SECONDS)
    ap.add_argument(
        "--output",
        default="data/benchmarks/benign_holdout/run_d_metrics.json",
        help="JSON summary output path",
    )
    args = ap.parse_args()

    summary = evaluate_holdout_run(
        corpus_dir=Path(args.corpus_dir),
        run_id=str(args.run_id),
        threshold=float(args.threshold),
        window_seconds=int(args.window_seconds),
    )
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(str(output_path), summary)

    print(
        "[benign-holdout] run=%s false_positive_windows=%d total_windows=%d alerts_per_minute=%.4f output=%s"
        % (
            summary["run_id"],
            int(summary["false_positive_windows"]),
            int(summary["total_windows"]),
            float(summary["alerts_per_minute"]),
            os.path.abspath(str(output_path)),
        )
    )


if __name__ == "__main__":
    main()
