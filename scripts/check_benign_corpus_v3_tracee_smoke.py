#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fp:
        payload = json.load(fp)
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Check benign corpus v3 Tracee smoke output.")
    parser.add_argument("output_dir", nargs="?", default="data/benign_corpus_v3/smoke/run_smoke_tracee")
    parser.add_argument("--allow-errors", action="store_true", help="report errors but do not fail on collection_summary.errors")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    failures: list[str] = []

    if not output_dir.is_dir():
        failures.append(f"missing output_dir: {output_dir}")

    required_files = [
        "run_meta.json",
        "driver.log",
        "request_events.jsonl",
        "workload_summary.json",
        "collection_summary.json",
    ]
    for name in required_files:
        if not (output_dir / name).is_file():
            failures.append(f"missing file: {output_dir / name}")

    events_path = output_dir / "request_events.jsonl"
    if events_path.is_file():
        with events_path.open("r", encoding="utf-8") as fp:
            line_count = sum(1 for line in fp if line.strip())
        if line_count < 1:
            failures.append(f"request_events.jsonl has no events: {events_path}")

    summary_path = output_dir / "collection_summary.json"
    if summary_path.is_file():
        try:
            summary = read_json(summary_path)
        except Exception as exc:
            failures.append(f"invalid collection_summary.json: {exc}")
            summary = {}
        driver = dict(summary.get("driver") or {})
        tracee = dict(summary.get("tracee") or {})
        errors = list(summary.get("errors") or [])

        if int(driver.get("exit_code", -1)) != 0:
            failures.append(f"driver.exit_code is not 0: {driver.get('exit_code')}")
        for key in ("run_meta_exists", "request_events_exists", "workload_summary_exists"):
            if not bool(driver.get(key)):
                failures.append(f"driver artifact flag is false: {key}")

        if bool(tracee.get("enabled")):
            trace_path = output_dir / str(tracee.get("trace_log") or "trace.log")
            if not trace_path.is_file():
                failures.append(f"tracee enabled but trace.log is missing: {trace_path}")
            elif trace_path.stat().st_size <= 0:
                failures.append(f"tracee enabled but trace.log is empty: {trace_path}")
            if not bool(tracee.get("trace_log_exists")):
                failures.append("collection_summary trace_log_exists is false")
            if int(tracee.get("trace_log_size_bytes") or 0) <= 0:
                failures.append("collection_summary trace_log_size_bytes is not positive")

        if errors and not args.allow_errors:
            failures.append(f"collection_summary.errors is not empty: {errors}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        raise SystemExit(1)

    print(f"OK: benign corpus v3 tracee smoke output looks valid: {output_dir}")


if __name__ == "__main__":
    main()
