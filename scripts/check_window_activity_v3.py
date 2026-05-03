#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_FIELDS = {
    "window_id",
    "run_id",
    "split",
    "start_ts",
    "end_ts",
    "request_count",
    "raw_event_count",
    "node_count",
    "edge_count",
    "activity_level",
}
VALID_LEVELS = {"empty", "idle", "low_activity", "active", "burst"}


def parse_ts(value: Any) -> datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fp:
        payload = json.load(fp)
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def count_nonempty_lines(path: Path) -> int:
    if not path.exists() or path.stat().st_size <= 0:
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as fp:
        return sum(1 for line in fp if line.strip())


def summary_records_trace_parse_failed(summary: dict[str, Any]) -> bool:
    warnings = [str(item) for item in summary.get("warnings") or []]
    errors = [str(item) for item in summary.get("errors") or []]
    return any("trace_parse_failed" in item for item in warnings + errors)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check benign corpus v3 window activity outputs.")
    parser.add_argument("--run-dir", required=True, help="Run directory.")
    parser.add_argument("--activity", default="", help="window_activity.jsonl path.")
    parser.add_argument("--summary", default="", help="window_activity_summary.json path.")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir).expanduser().resolve()
    activity_path = Path(args.activity).expanduser().resolve() if args.activity else run_dir / "window_activity.jsonl"
    summary_path = Path(args.summary).expanduser().resolve() if args.summary else run_dir / "window_activity_summary.json"
    failures: list[str] = []

    if not activity_path.is_file():
        failures.append(f"missing window_activity.jsonl: {activity_path}")
    if not summary_path.is_file():
        failures.append(f"missing window_activity_summary.json: {summary_path}")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    rows: list[dict[str, Any]] = []
    with activity_path.open("r", encoding="utf-8") as fp:
        for line_no, line in enumerate(fp, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception as exc:
                failures.append(f"line {line_no} is not valid JSON: {exc}")
                continue
            if not isinstance(row, dict):
                failures.append(f"line {line_no} is not a JSON object")
                continue
            missing = sorted(REQUIRED_FIELDS - set(row))
            if missing:
                failures.append(f"line {line_no} missing fields: {missing}")
            level = str(row.get("activity_level") or "")
            if level not in VALID_LEVELS:
                failures.append(f"line {line_no} invalid activity_level: {level}")
            rows.append(row)

    try:
        summary = read_json(summary_path)
    except Exception as exc:
        summary = {}
        failures.append(f"invalid summary JSON: {exc}")

    previous_end: datetime | None = None
    for idx, row in enumerate(rows, start=1):
        try:
            start = parse_ts(row.get("start_ts"))
            end = parse_ts(row.get("end_ts"))
        except Exception as exc:
            failures.append(f"line {idx} invalid timestamps: {exc}")
            continue
        if end <= start:
            failures.append(f"line {idx} end_ts is not after start_ts")
        if previous_end is not None and start != previous_end:
            failures.append(f"line {idx} window is not continuous with previous end")
        previous_end = end

    if int(summary.get("window_count") or -1) != len(rows):
        failures.append(f"summary window_count != jsonl rows: {summary.get('window_count')} != {len(rows)}")

    request_events_path = run_dir / "request_events.jsonl"
    if count_nonempty_lines(request_events_path) > 0:
        total_requests = sum(int(row.get("request_count") or 0) for row in rows)
        if total_requests <= 0:
            failures.append("request_events.jsonl is non-empty but total request_count is 0")

    trace_path = run_dir / "trace.log"
    if trace_path.exists() and trace_path.stat().st_size > 0:
        total_raw_events = sum(int(row.get("raw_event_count") or 0) for row in rows)
        if total_raw_events <= 0 and not summary_records_trace_parse_failed(summary):
            failures.append("trace.log is non-empty but total raw_event_count is 0 and summary has no trace_parse_failed warning")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print(f"OK: window activity output is valid: {activity_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
