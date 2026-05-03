#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


VALID_LEVELS = {"empty", "idle", "low_activity", "active", "burst"}


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fp:
        payload = json.load(fp)
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def read_jsonl(path: Path, failures: list[str], label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        failures.append(f"missing {label}: {path}")
        return rows
    with path.open("r", encoding="utf-8") as fp:
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


def level_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(str(row.get("activity_level") or "") for row in rows)
    return {level: int(counter.get(level, 0)) for level in sorted(VALID_LEVELS)}


def split_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(str(row.get("split") or "") for row in rows)
    return dict(sorted(counter.items()))


def main() -> int:
    parser = argparse.ArgumentParser(description="Check benign corpus v3 manifest outputs.")
    parser.add_argument("--corpus-dir", required=True, help="Benign corpus root directory.")
    parser.add_argument("--strict", action="store_true", help="Also check referenced run_meta/window_activity files.")
    args = parser.parse_args()

    corpus_dir = Path(args.corpus_dir).expanduser().resolve()
    manifest_path = corpus_dir / "corpus_manifest.json"
    summary_path = corpus_dir / "corpus_summary.json"
    full_index_path = corpus_dir / "full_window_index.jsonl"
    sampled_path = corpus_dir / "sampled_train_windows.jsonl"
    failures: list[str] = []

    for path, label in (
        (manifest_path, "corpus_manifest.json"),
        (summary_path, "corpus_summary.json"),
        (full_index_path, "full_window_index.jsonl"),
        (sampled_path, "sampled_train_windows.jsonl"),
    ):
        if not path.is_file():
            failures.append(f"missing {label}: {path}")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    try:
        manifest = read_json(manifest_path)
    except Exception as exc:
        manifest = {}
        failures.append(f"invalid corpus_manifest.json: {exc}")
    try:
        summary = read_json(summary_path)
    except Exception as exc:
        summary = {}
        failures.append(f"invalid corpus_summary.json: {exc}")

    full_rows = read_jsonl(full_index_path, failures, "full_window_index.jsonl")
    sampled_rows = read_jsonl(sampled_path, failures, "sampled_train_windows.jsonl")

    full_keys = {(str(row.get("split") or ""), str(row.get("run_id") or ""), str(row.get("window_id") or "")) for row in full_rows}
    full_window_ids = {str(row.get("window_id") or "") for row in full_rows}

    for idx, row in enumerate(full_rows, start=1):
        level = str(row.get("activity_level") or "")
        if level not in VALID_LEVELS:
            failures.append(f"full_window_index row {idx} invalid activity_level: {level}")
        if not row.get("split") or not row.get("run_id") or not row.get("window_id"):
            failures.append(f"full_window_index row {idx} missing split/run_id/window_id")
        if args.strict:
            for field in ("run_meta_path", "window_activity_path"):
                rel = row.get(field)
                if not rel or not (corpus_dir / str(rel)).is_file():
                    failures.append(f"full_window_index row {idx} missing referenced {field}: {rel}")

    for idx, row in enumerate(sampled_rows, start=1):
        split = str(row.get("split") or "")
        level = str(row.get("activity_level") or "")
        key = (split, str(row.get("run_id") or ""), str(row.get("window_id") or ""))
        if split != "train":
            failures.append(f"sampled row {idx} is not train split: {split}")
        if level == "empty":
            failures.append(f"sampled row {idx} contains empty window: {row.get('window_id')}")
        if level not in VALID_LEVELS:
            failures.append(f"sampled row {idx} invalid activity_level: {level}")
        if key not in full_keys:
            failures.append(f"sampled row {idx} not found in full index: {key}")
        if str(row.get("window_id") or "") not in full_window_ids:
            failures.append(f"sampled row {idx} window_id not found in full index: {row.get('window_id')}")

    manifest_splits = dict(manifest.get("splits") or {})
    actual_split_counts = split_counts(full_rows)
    for split, payload_raw in sorted(manifest_splits.items()):
        payload = dict(payload_raw or {})
        expected = int(payload.get("full_window_count") or 0)
        actual = int(actual_split_counts.get(split, 0))
        if expected != actual:
            failures.append(f"manifest split {split} full_window_count mismatch: {expected} != {actual}")
    train_manifest = dict(manifest_splits.get("train") or {})
    if int(train_manifest.get("sampled_window_count") or 0) != len(sampled_rows):
        failures.append(
            f"manifest train sampled_window_count mismatch: {train_manifest.get('sampled_window_count')} != {len(sampled_rows)}"
        )

    sampled_non_train = [row for row in sampled_rows if str(row.get("split") or "") != "train"]
    if sampled_non_train:
        failures.append("calibration/holdout or other non-train splits were sampled")

    constraints = dict(manifest.get("sampling") or {})
    max_idle = float(constraints.get("max_idle_fraction_in_sampled_train", 0.10))
    idle_count = sum(1 for row in sampled_rows if row.get("activity_level") == "idle")
    idle_fraction = float(idle_count / len(sampled_rows)) if sampled_rows else 0.0
    if idle_fraction > max_idle + 1e-12:
        failures.append(f"idle fraction exceeds limit: {idle_fraction:.6f} > {max_idle:.6f}")

    sampled_counts = level_counts(sampled_rows)
    if sampled_counts.get("empty", 0) > 0:
        failures.append("sampled_train_windows contains empty windows")

    if int(summary.get("total_full_windows", -1)) != len(full_rows):
        failures.append(f"summary total_full_windows mismatch: {summary.get('total_full_windows')} != {len(full_rows)}")
    if int(summary.get("total_sampled_train_windows", -1)) != len(sampled_rows):
        failures.append(
            f"summary total_sampled_train_windows mismatch: {summary.get('total_sampled_train_windows')} != {len(sampled_rows)}"
        )

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print(f"OK: benign corpus v3 manifest is valid: {corpus_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
