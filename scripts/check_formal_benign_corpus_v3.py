#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


VALID_LEVELS = {"empty", "idle", "low_activity", "active", "burst"}
DEFAULT_RUN_SPLITS = {
    "run_a": "train",
    "run_b": "train",
    "run_c": "calibration",
    "run_d": "holdout",
}


def read_json(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"missing {label}: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        failures.append(f"invalid {label}: {exc}")
        return {}
    if not isinstance(payload, dict):
        failures.append(f"invalid {label}: expected JSON object")
        return {}
    return payload


def read_jsonl(path: Path, failures: list[str], label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        failures.append(f"missing {label}: {path}")
        return rows
    with path.open("r", encoding="utf-8", errors="ignore") as fp:
        for line_no, line in enumerate(fp, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception as exc:
                failures.append(f"{label}:{line_no}: invalid JSON: {exc}")
                continue
            if not isinstance(payload, dict):
                failures.append(f"{label}:{line_no}: expected JSON object")
                continue
            rows.append(payload)
    return rows


def count_nonempty_lines(path: Path) -> int:
    if not path.exists() or path.stat().st_size <= 0:
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as fp:
        return sum(1 for line in fp if line.strip())


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return int(default)


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def selected_run_splits(runs: str) -> dict[str, str]:
    if not runs:
        return dict(DEFAULT_RUN_SPLITS)
    selected = parse_csv(runs)
    unknown = sorted(run_id for run_id in selected if run_id not in DEFAULT_RUN_SPLITS)
    if unknown:
        raise ValueError(f"unknown run id(s): {','.join(unknown)}")
    return {run_id: DEFAULT_RUN_SPLITS[run_id] for run_id in selected}


def activity_counts(rows: list[dict[str, Any]]) -> Counter[str]:
    return Counter(str(row.get("activity_level") or "") for row in rows)


def check_run(
    *,
    corpus_dir: Path,
    run_id: str,
    split: str,
    allow_missing_trace: bool,
    strict: bool,
    failures: list[str],
    warnings: list[str],
) -> int:
    run_dir = corpus_dir / split / run_id
    if not run_dir.is_dir():
        failures.append(f"missing run dir: {split}/{run_id}")
        return 0

    required = [
        "effective_config.yaml",
        "run_meta.json",
        "driver.log",
        "request_events.jsonl",
        "workload_summary.json",
        "collection_summary.json",
        "window_activity.jsonl",
        "window_activity_summary.json",
    ]
    if not allow_missing_trace:
        required.append("trace.log")
    for name in required:
        path = run_dir / name
        if not path.is_file():
            failures.append(f"missing {split}/{run_id}/{name}")
        elif name in {"trace.log", "request_events.jsonl", "window_activity.jsonl"} and path.stat().st_size <= 0:
            failures.append(f"empty {split}/{run_id}/{name}")

    request_lines = count_nonempty_lines(run_dir / "request_events.jsonl")
    if request_lines <= 0:
        failures.append(f"{split}/{run_id}: request_events.jsonl has no rows")

    workload = read_json(run_dir / "workload_summary.json", failures, f"{split}/{run_id}/workload_summary.json")
    if safe_int(workload.get("total_requests"), 0) <= 0:
        failures.append(f"{split}/{run_id}: workload_summary total_requests <= 0")

    collection = read_json(run_dir / "collection_summary.json", failures, f"{split}/{run_id}/collection_summary.json")
    driver = dict(collection.get("driver") or {})
    if safe_int(driver.get("exit_code"), -1) != 0:
        failures.append(f"{split}/{run_id}: driver.exit_code != 0 ({driver.get('exit_code')})")
    if not allow_missing_trace:
        trace_path = run_dir / "trace.log"
        if not trace_path.is_file() or trace_path.stat().st_size <= 0:
            failures.append(f"{split}/{run_id}: trace.log missing or empty")

    activity_rows = read_jsonl(run_dir / "window_activity.jsonl", failures, f"{split}/{run_id}/window_activity.jsonl")
    if not activity_rows:
        failures.append(f"{split}/{run_id}: window_activity.jsonl has no rows")
    for idx, row in enumerate(activity_rows, start=1):
        level = str(row.get("activity_level") or "")
        if level not in VALID_LEVELS:
            failures.append(f"{split}/{run_id}: window {idx} invalid activity_level={level}")
        if str(row.get("split") or "") != split:
            failures.append(f"{split}/{run_id}: window {idx} split mismatch: {row.get('split')}")
        if str(row.get("run_id") or "") != run_id:
            failures.append(f"{split}/{run_id}: window {idx} run_id mismatch: {row.get('run_id')}")

    effective = read_json(run_dir / "effective_config.yaml", failures, f"{split}/{run_id}/effective_config.yaml")
    run_meta = read_json(run_dir / "run_meta.json", failures, f"{split}/{run_id}/run_meta.json")
    if str(run_meta.get("split") or "") != split:
        failures.append(f"{split}/{run_id}: run_meta split mismatch: {run_meta.get('split')}")
    if safe_int(run_meta.get("random_seed"), -1) != safe_int(effective.get("random_seed"), -2):
        failures.append(f"{split}/{run_id}: run_meta random_seed != effective_config random_seed")
    if str(effective.get("split") or "") != split:
        failures.append(f"{split}/{run_id}: effective_config split mismatch: {effective.get('split')}")
    if str(effective.get("run_id") or "") != run_id:
        failures.append(f"{split}/{run_id}: effective_config run_id mismatch: {effective.get('run_id')}")

    if strict and collection.get("errors"):
        failures.append(f"{split}/{run_id}: collection_summary has errors: {collection.get('errors')}")
    elif collection.get("errors"):
        warnings.append(f"{split}/{run_id}: collection_summary has errors: {collection.get('errors')}")
    return sum(1 for row in activity_rows if str(row.get("activity_level") or "") != "empty")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check formal benign corpus v3 outputs.")
    parser.add_argument("--corpus-dir", required=True, help="Formal benign corpus root.")
    parser.add_argument("--allow-missing-trace", action="store_true", help="Allow skip-tracee collection outputs.")
    parser.add_argument("--strict", action="store_true", help="Promote quality warnings to failures.")
    parser.add_argument("--min-nonempty-windows", type=int, default=120, help="Minimum non-empty windows across checked runs.")
    parser.add_argument("--max-idle-empty-fraction", type=float, default=0.30, help="Warn/fail if full corpus idle+empty fraction exceeds this.")
    parser.add_argument("--runs", default="", help="Optional comma-separated run IDs to check.")
    args = parser.parse_args(argv)

    corpus_dir = Path(args.corpus_dir).expanduser().resolve()
    failures: list[str] = []
    warnings: list[str] = []
    try:
        run_splits = selected_run_splits(args.runs)
    except Exception as exc:
        print(f"FAIL: {exc}")
        return 2

    if not corpus_dir.is_dir():
        print(f"FAIL: corpus_dir does not exist: {corpus_dir}")
        return 1

    nonempty_windows = 0
    for run_id, split in run_splits.items():
        nonempty_windows += check_run(
            corpus_dir=corpus_dir,
            run_id=run_id,
            split=split,
            allow_missing_trace=bool(args.allow_missing_trace),
            strict=bool(args.strict),
            failures=failures,
            warnings=warnings,
        )

    manifest = read_json(corpus_dir / "corpus_manifest.json", failures, "corpus_manifest.json")
    summary = read_json(corpus_dir / "corpus_summary.json", failures, "corpus_summary.json")
    full_rows = read_jsonl(corpus_dir / "full_window_index.jsonl", failures, "full_window_index.jsonl")
    sampled_rows = read_jsonl(corpus_dir / "sampled_train_windows.jsonl", failures, "sampled_train_windows.jsonl")

    for idx, row in enumerate(full_rows, start=1):
        level = str(row.get("activity_level") or "")
        if level not in VALID_LEVELS:
            failures.append(f"full_window_index row {idx} invalid activity_level={level}")
    sampled_run_ids = {str(row.get("run_id") or "") for row in sampled_rows}
    for idx, row in enumerate(sampled_rows, start=1):
        split = str(row.get("split") or "")
        level = str(row.get("activity_level") or "")
        if split != "train":
            failures.append(f"sampled_train_windows row {idx} is not train: {split}")
        if str(row.get("run_id") or "") not in {"run_a", "run_b"}:
            failures.append(f"sampled_train_windows row {idx} has non-train run_id: {row.get('run_id')}")
        if level == "empty":
            failures.append(f"sampled_train_windows row {idx} contains empty window")
        if level not in VALID_LEVELS:
            failures.append(f"sampled_train_windows row {idx} invalid activity_level={level}")
    if any(run_id in sampled_run_ids for run_id in {"run_c", "run_d"}):
        failures.append("calibration or holdout run was sampled into sampled_train_windows")

    train_full = sum(1 for row in full_rows if str(row.get("split") or "") == "train")
    if train_full <= 0:
        failures.append("train full_window_count <= 0")
    if len(sampled_rows) <= 0:
        failures.append("sampled_train_windows has no rows")
    if nonempty_windows < int(args.min_nonempty_windows):
        failures.append(f"nonempty window count below minimum: {nonempty_windows} < {args.min_nonempty_windows}")

    full_counts = activity_counts(full_rows)
    idle_empty_count = int(full_counts.get("idle", 0)) + int(full_counts.get("empty", 0))
    idle_empty_fraction = float(idle_empty_count / len(full_rows)) if full_rows else 0.0
    if idle_empty_fraction > float(args.max_idle_empty_fraction):
        message = f"idle+empty fraction high: {idle_empty_fraction:.6f} > {args.max_idle_empty_fraction:.6f}"
        (failures if args.strict else warnings).append(message)

    manifest_splits = dict(manifest.get("splits") or {})
    train_manifest = dict(manifest_splits.get("train") or {})
    if safe_int(train_manifest.get("sampled_window_count"), -1) != len(sampled_rows):
        failures.append(
            f"manifest train sampled_window_count mismatch: {train_manifest.get('sampled_window_count')} != {len(sampled_rows)}"
        )
    if safe_int(summary.get("total_sampled_train_windows"), -1) != len(sampled_rows):
        failures.append(
            f"corpus_summary total_sampled_train_windows mismatch: {summary.get('total_sampled_train_windows')} != {len(sampled_rows)}"
        )

    report = read_json(corpus_dir / "formal_benign_collection_report.json", failures, "formal_benign_collection_report.json")
    report_errors = list(report.get("errors") or [])
    if report_errors:
        failures.append(f"formal report has errors: {report_errors}")
    for run_id, expected_split in run_splits.items():
        run_report = dict((report.get("runs") or {}).get(run_id) or {})
        if str(run_report.get("split") or "") != expected_split:
            failures.append(f"report {run_id} split mismatch: {run_report.get('split')}")
        if str(run_report.get("status") or "") not in {"success", "skipped"}:
            failures.append(f"report {run_id} status is not success/skipped: {run_report.get('status')}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        for warning in warnings:
            print(f"WARN: {warning}")
        return 1
    for warning in warnings:
        print(f"WARN: {warning}")
    print(f"OK: formal benign corpus v3 is valid: {corpus_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
