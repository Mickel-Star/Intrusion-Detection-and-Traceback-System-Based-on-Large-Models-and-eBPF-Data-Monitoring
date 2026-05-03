#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ACTIVITY_LEVELS = ("empty", "idle", "low_activity", "active", "burst")
DEFAULT_INCLUDE_SPLITS = ("train", "calibration", "holdout")
DEFAULT_POLICY_VERSION = "benign_manifest_v3_default"
DEFAULT_TRAIN_POLICY: dict[str, float] = {
    "active": 1.0,
    "burst": 1.0,
    "low_activity": 0.5,
    "idle": 0.1,
    "empty": 0.0,
}
DEFAULT_SAMPLING = {
    "min_train_windows": 100,
    "max_idle_fraction_in_sampled_train": 0.10,
    "max_empty_fraction_in_sampled_train": 0.00,
    "stratified_by_run": True,
    "stratified_by_activity_level": True,
}
KNOWN_WINDOWS_DIRS = ("windows", "processed_windows", "debug_windows", "persisted_windows", "realtime_windows")


def utc_now_str() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size <= 0:
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fp:
        for line_no, line in enumerate(fp, start=1):
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            rows.append(payload)
    return rows


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fp:
        for row in rows:
            fp.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def load_mapping(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size <= 0:
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(text)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        pass
    try:
        import yaml  # type: ignore

        payload = yaml.safe_load(text)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def relpath(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return os.path.relpath(str(path), str(root))


def path_for_manifest(path: Path) -> str:
    try:
        return os.path.relpath(str(path.resolve()), os.getcwd())
    except Exception:
        return str(path)


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return int(default)


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def safe_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def stable_random(seed: int, *parts: str) -> random.Random:
    digest = hashlib.sha256((":".join([str(seed), *parts])).encode("utf-8")).hexdigest()
    return random.Random(int(digest[:16], 16))


def output_exists(paths: list[Path]) -> list[Path]:
    return [path for path in paths if path.exists()]


def load_sampling_config(path: Path, warnings: list[str]) -> dict[str, Any]:
    if not path.exists():
        warnings.append(f"sampling_config_not_found_using_defaults:{path}")
        return {}
    payload = load_mapping(path)
    if not payload:
        warnings.append(f"sampling_config_parse_failed_using_defaults:{path}")
    return payload


def split_config(payload: dict[str, Any], split: str) -> dict[str, Any]:
    splits = payload.get("splits")
    if isinstance(splits, dict) and isinstance(splits.get(split), dict):
        return dict(splits.get(split) or {})
    return {}


def train_sampling_policy(config: dict[str, Any]) -> dict[str, float]:
    raw = split_config(config, "train").get("sampling_policy")
    policy = dict(DEFAULT_TRAIN_POLICY)
    if isinstance(raw, dict):
        for level in ACTIVITY_LEVELS:
            if level in raw:
                policy[level] = max(min(safe_float(raw.get(level), policy[level]), 1.0), 0.0)
    return policy


def sampling_constraints(config: dict[str, Any]) -> dict[str, Any]:
    constraints = dict(DEFAULT_SAMPLING)
    raw = config.get("sampling")
    if isinstance(raw, dict):
        for key in list(constraints):
            if key not in raw:
                continue
            if isinstance(constraints[key], bool):
                constraints[key] = safe_bool(raw.get(key), bool(constraints[key]))
            elif isinstance(constraints[key], int):
                constraints[key] = safe_int(raw.get(key), int(constraints[key]))
            else:
                constraints[key] = safe_float(raw.get(key), float(constraints[key]))
    return constraints


def configured_runs(config: dict[str, Any], split: str) -> list[str]:
    raw = split_config(config, split).get("runs")
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    if isinstance(raw, str):
        return parse_csv(raw)
    return []


def discover_run_dirs(corpus_dir: Path, split: str, config: dict[str, Any], warnings: list[str], errors: list[str], strict: bool) -> list[Path]:
    split_dir = corpus_dir / split
    requested = configured_runs(config, split)
    run_dirs: list[Path] = []
    if requested:
        for run_id in requested:
            path = split_dir / run_id
            if path.is_dir():
                run_dirs.append(path)
            else:
                message = f"configured_run_missing:{split}/{run_id}"
                (errors if strict else warnings).append(message)
        return sorted(run_dirs, key=lambda item: item.name)

    if not split_dir.exists():
        warnings.append(f"split_dir_missing:{split}")
        return []
    if not split_dir.is_dir():
        message = f"split_path_not_directory:{split}"
        (errors if strict else warnings).append(message)
        return []
    return sorted([path for path in split_dir.iterdir() if path.is_dir()], key=lambda item: item.name)


def maybe_add_smoke_split(corpus_dir: Path, include_splits: list[str], warnings: list[str]) -> list[str]:
    if any((corpus_dir / split).is_dir() for split in include_splits):
        return include_splits
    if "smoke" not in include_splits and (corpus_dir / "smoke").is_dir():
        warnings.append("default_splits_missing_using_smoke_split")
        return [*include_splits, "smoke"]
    return include_splits


def infer_window_graph_path(run_dir: Path, window_id: str, sequence: int) -> tuple[Path | None, Path | None]:
    candidates: list[Path] = []
    for name in KNOWN_WINDOWS_DIRS:
        windows_dir = run_dir / name
        if not windows_dir.is_dir():
            continue
        candidates.extend(
            [
                windows_dir / f"window_{sequence:04d}.json",
                windows_dir / f"window_{sequence:06d}.json",
                windows_dir / f"{window_id}.json",
            ]
        )
        for candidate in candidates:
            if candidate.is_file():
                return candidate, windows_dir
    return None, None


def normalize_window_record(
    *,
    corpus_dir: Path,
    split: str,
    run_dir: Path,
    run_meta: dict[str, Any],
    row: dict[str, Any],
    sequence: int,
    warnings: list[str],
) -> dict[str, Any]:
    run_id = str(row.get("run_id") or run_meta.get("run_id") or run_dir.name)
    window_id = str(row.get("window_id") or f"{run_id}_w{sequence:06d}")
    trace_path = run_dir / "trace.log"
    run_meta_path = run_dir / "run_meta.json"
    activity_path = run_dir / "window_activity.jsonl"
    activity_summary = read_json(run_dir / "window_activity_summary.json")
    graph_path, windows_dir = infer_window_graph_path(run_dir, window_id, sequence)
    graph_stats_source = str(activity_summary.get("graph_stats_source") or row.get("graph_stats_source") or "")
    if graph_path is None:
        warnings.append(f"window_graph_path_unavailable:{split}/{run_dir.name}/{window_id}")

    if not trace_path.exists():
        trace_log_path: str | None = None
    else:
        trace_log_path = relpath(trace_path, corpus_dir)
    return {
        "dataset": str(row.get("dataset") or run_meta.get("dataset") or "benign_corpus_v3"),
        "split": split,
        "run_id": run_id,
        "window_id": window_id,
        "window_sequence": int(sequence),
        "start_ts": row.get("start_ts"),
        "end_ts": row.get("end_ts"),
        "duration_seconds": safe_int(row.get("duration_seconds"), 30),
        "activity_level": str(row.get("activity_level") or "empty"),
        "dominant_phase": row.get("dominant_phase"),
        "active_roles": list(row.get("active_roles") or []),
        "dominant_profiles": list(row.get("dominant_profiles") or []),
        "request_count": safe_int(row.get("request_count"), 0),
        "success_count": safe_int(row.get("success_count"), 0),
        "failure_count": safe_int(row.get("failure_count"), 0),
        "retry_count": safe_int(row.get("retry_count"), 0),
        "raw_event_count": safe_int(row.get("raw_event_count"), 0),
        "node_count": safe_int(row.get("node_count"), 0),
        "edge_count": safe_int(row.get("edge_count"), 0),
        "unique_process_count": safe_int(row.get("unique_process_count"), 0),
        "unique_file_count": safe_int(row.get("unique_file_count"), 0),
        "unique_net_count": safe_int(row.get("unique_net_count"), 0),
        "window_activity_path": relpath(activity_path, corpus_dir),
        "window_activity_summary_path": relpath(run_dir / "window_activity_summary.json", corpus_dir)
        if (run_dir / "window_activity_summary.json").exists()
        else None,
        "trace_log_path": trace_log_path,
        "run_meta_path": relpath(run_meta_path, corpus_dir) if run_meta_path.exists() else None,
        "window_graph_path": relpath(graph_path, corpus_dir) if graph_path else None,
        "windows_dir": relpath(windows_dir, corpus_dir) if windows_dir else None,
        "graph_stats_source": graph_stats_source or ("windows_dir" if graph_path else "unavailable"),
    }


def load_run_windows(
    *,
    corpus_dir: Path,
    split: str,
    run_dir: Path,
    strict: bool,
    warnings: list[str],
    errors: list[str],
) -> list[dict[str, Any]]:
    activity_path = run_dir / "window_activity.jsonl"
    run_meta_path = run_dir / "run_meta.json"
    if not run_meta_path.exists():
        message = f"missing_run_meta:{split}/{run_dir.name}"
        (errors if strict else warnings).append(message)
    run_meta = read_json(run_meta_path)

    if not activity_path.exists() or activity_path.stat().st_size <= 0:
        message = f"missing_window_activity:{split}/{run_dir.name}"
        (errors if strict else warnings).append(message)
        return []

    try:
        rows = read_jsonl(activity_path)
    except Exception as exc:
        message = f"window_activity_parse_failed:{split}/{run_dir.name}:{type(exc).__name__}"
        (errors if strict else warnings).append(message)
        return []

    records = []
    for sequence, row in enumerate(rows, start=1):
        record = normalize_window_record(
            corpus_dir=corpus_dir,
            split=split,
            run_dir=run_dir,
            run_meta=run_meta,
            row=row,
            sequence=sequence,
            warnings=warnings,
        )
        if record["activity_level"] not in ACTIVITY_LEVELS:
            message = f"invalid_activity_level:{split}/{run_dir.name}/{record['window_id']}:{record['activity_level']}"
            (errors if strict else warnings).append(message)
        if str(row.get("split") or split) != split:
            warnings.append(f"window_split_mismatch:{split}/{run_dir.name}/{record['window_id']}:{row.get('split')}")
        records.append(record)
    return records


def activity_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(str(record.get("activity_level") or "empty") for record in records)
    return {level: int(counter.get(level, 0)) for level in ACTIVITY_LEVELS}


def summarize_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    per_run = Counter(str(record.get("run_id") or "") for record in records)
    per_role: Counter[str] = Counter()
    per_profile: Counter[str] = Counter()
    for record in records:
        for role in list(record.get("active_roles") or []):
            if str(role):
                per_role[str(role)] += 1
        for profile in list(record.get("dominant_profiles") or []):
            if str(profile):
                per_profile[str(profile)] += 1
    return {
        "full_window_count": int(len(records)),
        "activity_level_counts_full": activity_counts(records),
        "per_run_counts": dict(sorted(per_run.items())),
        "per_role_counts": dict(sorted(per_role.items())),
        "per_profile_counts": dict(sorted(per_profile.items())),
        "request_count_total": int(sum(safe_int(record.get("request_count"), 0) for record in records)),
        "raw_event_count_total": int(sum(safe_int(record.get("raw_event_count"), 0) for record in records)),
        "edge_count_total": int(sum(safe_int(record.get("edge_count"), 0) for record in records)),
        "node_count_total": int(sum(safe_int(record.get("node_count"), 0) for record in records)),
    }


def sample_train_windows(
    train_records: list[dict[str, Any]],
    *,
    seed: int,
    policy: dict[str, float],
    constraints: dict[str, Any],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in train_records:
        grouped[(str(record.get("run_id") or ""), str(record.get("activity_level") or "empty"))].append(record)

    sampled: list[dict[str, Any]] = []
    for (run_id, level), records in sorted(grouped.items()):
        ordered = sorted(records, key=lambda item: str(item.get("window_id") or ""))
        ratio = max(min(float(policy.get(level, 0.0)), 1.0), 0.0)
        if ratio >= 1.0:
            chosen = ordered
        elif ratio <= 0.0:
            chosen = []
        else:
            rng = stable_random(seed, run_id, level)
            chosen = [record for record in ordered if rng.random() < ratio]
        for record in chosen:
            out = sampled_record(record, ratio)
            sampled.append(out)

    sampled = enforce_idle_fraction(sampled, seed=seed, max_idle_fraction=safe_float(constraints.get("max_idle_fraction_in_sampled_train"), 0.10))
    return sorted(sampled, key=lambda item: (str(item.get("run_id") or ""), str(item.get("window_id") or "")))


def sampled_record(record: dict[str, Any], ratio: float) -> dict[str, Any]:
    level = str(record.get("activity_level") or "empty")
    return {
        "dataset": record.get("dataset"),
        "split": "train",
        "run_id": record.get("run_id"),
        "window_id": record.get("window_id"),
        "window_sequence": record.get("window_sequence"),
        "activity_level": level,
        "start_ts": record.get("start_ts"),
        "end_ts": record.get("end_ts"),
        "sampled": True,
        "sampling_reason": f"policy_{level}_{float(ratio):.3g}",
        "sampling_policy_version": DEFAULT_POLICY_VERSION,
        "window_activity_path": record.get("window_activity_path"),
        "trace_log_path": record.get("trace_log_path"),
        "run_meta_path": record.get("run_meta_path"),
        "window_graph_path": record.get("window_graph_path"),
        "windows_dir": record.get("windows_dir"),
        "graph_stats_source": record.get("graph_stats_source"),
        "node_count": safe_int(record.get("node_count"), 0),
        "edge_count": safe_int(record.get("edge_count"), 0),
        "request_count": safe_int(record.get("request_count"), 0),
        "raw_event_count": safe_int(record.get("raw_event_count"), 0),
    }


def enforce_idle_fraction(sampled: list[dict[str, Any]], *, seed: int, max_idle_fraction: float) -> list[dict[str, Any]]:
    if max_idle_fraction < 0:
        max_idle_fraction = 0.0
    if max_idle_fraction >= 1.0:
        return sampled
    idle = [record for record in sampled if record.get("activity_level") == "idle"]
    non_idle = [record for record in sampled if record.get("activity_level") != "idle"]
    if not idle:
        return sampled
    max_idle_count = int((max_idle_fraction * len(non_idle)) // max(1e-12, (1.0 - max_idle_fraction)))
    max_idle_count = max(max_idle_count, 0)
    if len(idle) <= max_idle_count:
        return sampled
    ordered = sorted(idle, key=lambda item: str(item.get("window_id") or ""))
    rng = stable_random(seed, "idle_fraction_cap")
    rng.shuffle(ordered)
    kept_idle_ids = {str(item.get("window_id") or "") for item in ordered[:max_idle_count]}
    return [record for record in sampled if record.get("activity_level") != "idle" or str(record.get("window_id") or "") in kept_idle_ids]


def detect_split_collisions(records: list[dict[str, Any]], warnings: list[str], errors: list[str], strict: bool) -> None:
    run_splits: dict[str, set[str]] = defaultdict(set)
    window_splits: dict[str, set[str]] = defaultdict(set)
    for record in records:
        run_splits[str(record.get("run_id") or "")].add(str(record.get("split") or ""))
        window_splits[str(record.get("window_id") or "")].add(str(record.get("split") or ""))
    for run_id, splits in sorted(run_splits.items()):
        if run_id and len(splits) > 1:
            message = f"run_id_in_multiple_splits:{run_id}:{','.join(sorted(splits))}"
            (errors if strict else warnings).append(message)
    for window_id, splits in sorted(window_splits.items()):
        if window_id and len(splits) > 1:
            message = f"window_id_in_multiple_splits:{window_id}:{','.join(sorted(splits))}"
            (errors if strict else warnings).append(message)


def build_split_manifest(
    split: str,
    records: list[dict[str, Any]],
    sampled: list[dict[str, Any]],
    train_policy: dict[str, float],
) -> dict[str, Any]:
    runs = sorted({str(record.get("run_id") or "") for record in records if str(record.get("run_id") or "")})
    payload = {
        "runs": runs,
        "keep_all_windows": split != "train",
        "full_window_count": int(len(records)),
        "activity_level_counts_full": activity_counts(records),
    }
    if split == "train":
        payload.update(
            {
                "keep_all_windows": False,
                "sampled_window_count": int(len(sampled)),
                "activity_level_counts_sampled": activity_counts(sampled),
                "sampling_policy": dict(sorted(train_policy.items())),
            }
        )
    return payload


def quality_checks(sampled: list[dict[str, Any]], constraints: dict[str, Any]) -> dict[str, Any]:
    total = len(sampled)
    empty_count = sum(1 for record in sampled if record.get("activity_level") == "empty")
    idle_count = sum(1 for record in sampled if record.get("activity_level") == "idle")
    active_or_burst = sum(1 for record in sampled if record.get("activity_level") in {"active", "burst"})
    return {
        "contains_empty_windows": bool(empty_count > 0),
        "idle_fraction": float(idle_count / total) if total else 0.0,
        "active_or_burst_fraction": float(active_or_burst / total) if total else 0.0,
        "min_train_windows_satisfied": bool(total >= safe_int(constraints.get("min_train_windows"), 100)),
    }


def build_manifest(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    corpus_dir = Path(args.corpus_dir).expanduser().resolve()
    output_manifest = Path(args.output_manifest).expanduser().resolve() if args.output_manifest else corpus_dir / "corpus_manifest.json"
    output_summary = Path(args.output_summary).expanduser().resolve() if args.output_summary else corpus_dir / "corpus_summary.json"
    output_full_index = Path(args.output_full_index).expanduser().resolve() if args.output_full_index else corpus_dir / "full_window_index.jsonl"
    output_sampled_train = (
        Path(args.output_sampled_train).expanduser().resolve() if args.output_sampled_train else corpus_dir / "sampled_train_windows.jsonl"
    )
    outputs = [output_manifest, output_summary, output_full_index, output_sampled_train]
    existing = output_exists(outputs)
    if existing and not bool(args.force):
        raise FileExistsError("output exists, pass --force to overwrite: " + ", ".join(str(path) for path in existing))

    warnings: list[str] = []
    errors: list[str] = []
    config_path = Path(args.sampling_config).expanduser().resolve() if args.sampling_config else Path("configs/benign_manifest_v3.yaml").resolve()
    config = load_sampling_config(config_path, warnings)
    include_splits = parse_csv(args.include_splits) if args.include_splits else list(DEFAULT_INCLUDE_SPLITS)
    if include_splits == list(DEFAULT_INCLUDE_SPLITS):
        include_splits = maybe_add_smoke_split(corpus_dir, include_splits, warnings)

    train_policy = train_sampling_policy(config)
    constraints = sampling_constraints(config)
    all_records: list[dict[str, Any]] = []
    records_by_split: dict[str, list[dict[str, Any]]] = {split: [] for split in include_splits}

    if not corpus_dir.exists():
        message = f"corpus_dir_missing:{corpus_dir}"
        if bool(args.allow_missing_runs):
            warnings.append(message)
        else:
            errors.append(message)
    else:
        for split in include_splits:
            run_dirs = discover_run_dirs(corpus_dir, split, config, warnings, errors, strict=bool(args.strict))
            if not run_dirs and bool(args.strict):
                errors.append(f"no_runs_for_split:{split}")
            for run_dir in run_dirs:
                records = load_run_windows(
                    corpus_dir=corpus_dir,
                    split=split,
                    run_dir=run_dir,
                    strict=bool(args.strict),
                    warnings=warnings,
                    errors=errors,
                )
                records_by_split.setdefault(split, []).extend(records)
                all_records.extend(records)

    detect_split_collisions(all_records, warnings, errors, strict=bool(args.strict))
    sampled_train = sample_train_windows(
        records_by_split.get("train", []),
        seed=int(args.seed),
        policy=train_policy,
        constraints=constraints,
    )

    if any(record.get("activity_level") == "empty" for record in sampled_train):
        errors.append("sampled_train_contains_empty_windows")
    if not quality_checks(sampled_train, constraints)["min_train_windows_satisfied"]:
        warnings.append(
            f"sampled_train_below_min_train_windows:{len(sampled_train)}<{safe_int(constraints.get('min_train_windows'), 100)}"
        )
    if any(record.get("window_graph_path") is None for record in all_records):
        warnings.append("window_graph_path_unavailable")

    created_at = utc_now_str()
    splits_manifest: dict[str, Any] = {}
    splits_summary: dict[str, Any] = {}
    for split in include_splits:
        split_records = records_by_split.get(split, [])
        split_sampled = sampled_train if split == "train" else []
        splits_manifest[split] = build_split_manifest(split, split_records, split_sampled, train_policy)
        split_summary = summarize_records(split_records)
        if split == "train":
            split_summary["sampled_window_count"] = int(len(sampled_train))
            split_summary["activity_level_counts_sampled"] = activity_counts(sampled_train)
        splits_summary[split] = split_summary

    manifest = {
        "dataset": str(config.get("dataset") or "benign_corpus_v3"),
        "version": "v3",
        "created_at": created_at,
        "window_seconds": int(args.window_seconds),
        "time_bin_seconds": int(args.time_bin_seconds),
        "random_seed": int(args.seed),
        "corpus_dir": path_for_manifest(corpus_dir),
        "files": {
            "full_window_index": relpath(output_full_index, corpus_dir),
            "sampled_train_windows": relpath(output_sampled_train, corpus_dir),
            "corpus_summary": relpath(output_summary, corpus_dir),
        },
        "splits": splits_manifest,
        "sampling": constraints,
        "sampling_policy_version": DEFAULT_POLICY_VERSION,
        "sampling_config": path_for_manifest(config_path) if config_path.exists() else None,
        "policy_notes": [
            "Only train split is sampled.",
            "Calibration and holdout preserve all windows.",
            "Attack data is not included.",
        ],
        "warnings": sorted(set(warnings)),
        "errors": sorted(set(errors)),
    }
    summary = {
        "dataset": manifest["dataset"],
        "created_at": created_at,
        "total_full_windows": int(len(all_records)),
        "total_sampled_train_windows": int(len(sampled_train)),
        "splits": splits_summary,
        "sampled_train_quality_checks": quality_checks(sampled_train, constraints),
        "warnings": sorted(set(warnings)),
        "errors": sorted(set(errors)),
    }

    write_jsonl(output_full_index, sorted(all_records, key=lambda item: (str(item.get("split")), str(item.get("run_id")), str(item.get("window_id")))))
    write_jsonl(output_sampled_train, sampled_train)
    write_json(output_manifest, manifest)
    write_json(output_summary, summary)

    if errors:
        raise RuntimeError("; ".join(sorted(set(errors))))
    return manifest, summary, all_records, sampled_train


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build benign corpus v3 sampled training manifest.")
    parser.add_argument("--corpus-dir", required=True, help="Benign corpus root directory.")
    parser.add_argument("--window-seconds", type=int, default=30, help="Window size in seconds.")
    parser.add_argument("--time-bin-seconds", type=int, default=2, help="Time bin size in seconds.")
    parser.add_argument("--seed", type=int, default=20260501, help="Sampling random seed.")
    parser.add_argument("--sampling-config", default="configs/benign_manifest_v3.yaml", help="Optional sampling config.")
    parser.add_argument("--output-manifest", default="", help="Output corpus_manifest.json path.")
    parser.add_argument("--output-summary", default="", help="Output corpus_summary.json path.")
    parser.add_argument("--output-full-index", default="", help="Output full_window_index.jsonl path.")
    parser.add_argument("--output-sampled-train", default="", help="Output sampled_train_windows.jsonl path.")
    parser.add_argument("--include-splits", default="train,calibration,holdout", help="Comma-separated split names.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing manifest outputs.")
    parser.add_argument("--strict", action="store_true", help="Fail on missing run_meta/window_activity or split collisions.")
    parser.add_argument("--allow-missing-runs", action="store_true", help="Allow missing corpus or configured runs with warnings.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(argv if argv is not None else sys.argv[1:]))
    try:
        manifest, summary, _full, sampled = build_manifest(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        "benign manifest built: "
        f"dataset={manifest.get('dataset')} full_windows={summary.get('total_full_windows')} "
        f"sampled_train={len(sampled)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
