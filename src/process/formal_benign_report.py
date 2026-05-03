#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.process.benign_workload_driver import load_config


ACTIVITY_LEVELS = ("empty", "idle", "low_activity", "active", "burst")
DEFAULT_RUN_ORDER = ("run_a", "run_b", "run_c", "run_d")
SPLITS = ("train", "calibration", "holdout")


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
    if not path.exists() or path.stat().st_size <= 0:
        return rows
    with path.open("r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
    return rows


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


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


def relpath(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return os.path.relpath(str(path), str(root))


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except Exception:
        return os.path.relpath(str(path), str(Path.cwd()))


def normalize_corpus_dir(config: dict[str, Any], corpus_dir: str, rehearsal: bool) -> Path:
    if corpus_dir:
        return Path(corpus_dir)
    key = "rehearsal_corpus_dir" if rehearsal else "corpus_dir"
    return Path(str(config.get(key) or config.get("corpus_dir") or "data/benign_corpus_v3"))


def ordered_run_ids(config: dict[str, Any]) -> list[str]:
    raw = config.get("runs")
    if not isinstance(raw, dict):
        return []
    known = [run_id for run_id in DEFAULT_RUN_ORDER if run_id in raw]
    extras = sorted(run_id for run_id in raw if run_id not in set(known))
    return [*known, *extras]


def selected_run_ids(config: dict[str, Any], runs: str) -> list[str]:
    all_ids = ordered_run_ids(config)
    if not runs:
        return all_ids
    requested = parse_csv(runs)
    known = set(all_ids)
    unknown = sorted(run_id for run_id in requested if run_id not in known)
    if unknown:
        raise ValueError(f"unknown run id(s): {','.join(unknown)}")
    return requested


def scaled_duration(value: Any, scale: float) -> int:
    return max(int(round(safe_float(value, 0.0) * float(scale))), 1)


def normalize_phases(run_id: str, run_cfg: dict[str, Any], scale: float) -> list[dict[str, Any]]:
    phases: list[dict[str, Any]] = []
    cursor = 0.0
    raw_phases = list(run_cfg.get("phases") or [])
    for idx, raw in enumerate(raw_phases, start=1):
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or raw.get("phase_id") or f"phase_{idx:02d}")
        duration = scaled_duration(raw.get("duration_seconds"), scale)
        phase = {
            "name": name,
            "phase_id": str(raw.get("phase_id") or name),
            "profile_id": str(raw.get("profile_id") or raw.get("profile") or name),
            "duration_seconds": int(duration),
            "source_duration_seconds": safe_int(raw.get("duration_seconds"), duration),
            "start_offset_seconds": float(cursor),
            "end_offset_seconds": float(cursor + duration),
        }
        phases.append(phase)
        cursor += duration
    if phases:
        return phases
    duration = scaled_duration(run_cfg.get("duration_seconds"), scale)
    return [
        {
            "name": f"{run_id}_single_phase",
            "phase_id": f"{run_id}_single_phase",
            "profile_id": f"{run_id}_single_phase",
            "duration_seconds": int(duration),
            "source_duration_seconds": safe_int(run_cfg.get("duration_seconds"), duration),
            "start_offset_seconds": 0.0,
            "end_offset_seconds": float(duration),
        }
    ]


def build_run_config(
    *,
    config: dict[str, Any],
    run_id: str,
    corpus_dir: Path,
    duration_scale: float,
    skip_tracee: bool,
    skip_compose_up: bool,
) -> dict[str, Any]:
    runs = dict(config.get("runs") or {})
    if run_id not in runs or not isinstance(runs.get(run_id), dict):
        raise ValueError(f"unknown run id: {run_id}")
    run_cfg = dict(runs[run_id] or {})
    split = str(run_cfg.get("split") or "")
    if not split:
        raise ValueError(f"run {run_id} missing split")

    phases = normalize_phases(run_id, run_cfg, duration_scale)
    duration_seconds = int(sum(safe_int(phase.get("duration_seconds"), 0) for phase in phases))
    output_dir = corpus_dir / split / run_id
    collection = dict(config.get("collection") or {})
    if skip_tracee:
        collection["tracee_enabled"] = False
    if skip_compose_up:
        collection["skip_compose_up"] = True

    actors = dict(config.get("actors") or {})
    for actor_name, override in dict(run_cfg.get("actors") or {}).items():
        if isinstance(override, dict) and isinstance(actors.get(actor_name), dict):
            merged = dict(actors.get(actor_name) or {})
            merged.update(override)
            actors[actor_name] = merged
        else:
            actors[actor_name] = override
    endpoints = dict(run_cfg.get("endpoints") or config.get("endpoints") or {})
    payload = {
        "dataset": str(config.get("dataset") or "benign_corpus_v3"),
        "version": str(config.get("version") or "v3"),
        "run_id": run_id,
        "split": split,
        "phase": "formal_benign_collection_v3",
        "base_url": str(run_cfg.get("base_url") or config.get("base_url") or "http://127.0.0.1:5000"),
        "duration_seconds": duration_seconds,
        "source_duration_seconds": safe_int(run_cfg.get("duration_seconds"), duration_seconds),
        "duration_scale": float(duration_scale),
        "random_seed": safe_int(run_cfg.get("random_seed"), safe_int(config.get("random_seed"), 0)),
        "output_dir": output_dir.as_posix(),
        "workload_model": str(config.get("workload_model") or "multi_actor_arrival_rate"),
        "request_timeout_seconds": safe_float(config.get("request_timeout_seconds"), 5.0),
        "window_seconds": safe_int(config.get("window_seconds"), 30),
        "time_bin_seconds": safe_int(config.get("time_bin_seconds"), 2),
        "collection": collection,
        "auth": dict(run_cfg.get("auth") or config.get("auth") or {}),
        "actors": actors,
        "endpoints": endpoints,
        "phases": phases,
        "split_semantics": {
            "train": "Use only for BBK/GMAE benign training sampling.",
            "calibration": "Use only for threshold or score calibration.",
            "holdout": "Use only for final benign false-positive evaluation.",
        }.get(split, ""),
    }
    return payload


def emit_plan(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    corpus_dir = normalize_corpus_dir(config, args.corpus_dir, bool(args.rehearsal))
    scale = safe_float(args.duration_scale, 1.0)
    if bool(args.rehearsal) and scale == 1.0:
        scale = 0.1
    for run_id in selected_run_ids(config, args.runs):
        run_cfg = build_run_config(
            config=config,
            run_id=run_id,
            corpus_dir=corpus_dir,
            duration_scale=scale,
            skip_tracee=bool(args.skip_tracee),
            skip_compose_up=bool(args.skip_compose_up),
        )
        print(
            "\t".join(
                [
                    str(run_cfg["run_id"]),
                    str(run_cfg["split"]),
                    str(run_cfg["output_dir"]),
                    str(run_cfg["duration_seconds"]),
                ]
            )
        )
    return 0


def write_run_config(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    corpus_dir = normalize_corpus_dir(config, args.corpus_dir, bool(args.rehearsal))
    scale = safe_float(args.duration_scale, 1.0)
    if bool(args.rehearsal) and scale == 1.0:
        scale = 0.1
    run_cfg = build_run_config(
        config=config,
        run_id=args.run_id,
        corpus_dir=corpus_dir,
        duration_scale=scale,
        skip_tracee=bool(args.skip_tracee),
        skip_compose_up=bool(args.skip_compose_up),
    )
    write_json(Path(args.output), run_cfg)
    return 0


def count_lines(path: Path) -> int:
    if not path.exists() or path.stat().st_size <= 0:
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as fp:
        return sum(1 for line in fp if line.strip())


def activity_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(str(row.get("activity_level") or "empty") for row in rows)
    return {level: int(counter.get(level, 0)) for level in ACTIVITY_LEVELS}


def split_rows(rows: list[dict[str, Any]], split: str) -> list[dict[str, Any]]:
    return [row for row in rows if str(row.get("split") or "") == split]


def validate_run_artifacts(
    *,
    corpus_dir: Path,
    run_id: str,
    selected: bool,
    run_cfg: dict[str, Any],
    no_window_activity: bool,
    allow_missing_trace: bool,
) -> dict[str, Any]:
    run_dir = Path(str(run_cfg.get("output_dir") or ""))
    if not run_dir.is_absolute():
        run_dir = (Path.cwd() / run_dir).resolve()
    collection = dict(run_cfg.get("collection") or {})
    tracee_enabled = safe_bool(collection.get("tracee_enabled"), True) and not allow_missing_trace
    warnings: list[str] = []
    errors: list[str] = []

    effective_config = read_json(run_dir / "effective_config.yaml")
    run_meta = read_json(run_dir / "run_meta.json")
    workload_summary = read_json(run_dir / "workload_summary.json")
    collection_summary = read_json(run_dir / "collection_summary.json")
    activity_rows = read_jsonl(run_dir / "window_activity.jsonl")
    activity_summary = read_json(run_dir / "window_activity_summary.json")

    required = [
        ("effective_config.yaml", run_dir / "effective_config.yaml"),
        ("run_meta.json", run_dir / "run_meta.json"),
        ("driver.log", run_dir / "driver.log"),
        ("request_events.jsonl", run_dir / "request_events.jsonl"),
        ("workload_summary.json", run_dir / "workload_summary.json"),
        ("collection_summary.json", run_dir / "collection_summary.json"),
    ]
    if tracee_enabled:
        required.append(("trace.log", run_dir / "trace.log"))
    if not no_window_activity:
        required.extend(
            [
                ("window_activity.jsonl", run_dir / "window_activity.jsonl"),
                ("window_activity_summary.json", run_dir / "window_activity_summary.json"),
            ]
        )
    if selected:
        for label, path in required:
            if not path.is_file():
                errors.append(f"missing_artifact:{label}")
            elif label in {"trace.log", "request_events.jsonl", "window_activity.jsonl"} and path.stat().st_size <= 0:
                errors.append(f"empty_artifact:{label}")

    request_count = safe_int(workload_summary.get("total_requests"), 0)
    success_count = safe_int(workload_summary.get("success_count"), 0)
    failure_count = safe_int(workload_summary.get("failure_count"), 0)
    if selected and count_lines(run_dir / "request_events.jsonl") <= 0:
        errors.append("request_events_empty")
    if selected and request_count <= 0:
        errors.append("workload_total_requests_not_positive")

    if selected and not no_window_activity:
        if not activity_rows:
            errors.append("window_activity_empty")
        invalid_levels = sorted(
            {
                str(row.get("activity_level") or "")
                for row in activity_rows
                if str(row.get("activity_level") or "") not in ACTIVITY_LEVELS
            }
        )
        if invalid_levels:
            errors.append(f"invalid_activity_levels:{','.join(invalid_levels)}")

    if selected and tracee_enabled and (not (run_dir / "trace.log").is_file() or (run_dir / "trace.log").stat().st_size <= 0):
        errors.append("trace_log_missing_or_empty")

    driver = dict(collection_summary.get("driver") or {})
    if selected and collection_summary and safe_int(driver.get("exit_code"), -1) != 0:
        errors.append(f"driver_exit_code:{safe_int(driver.get('exit_code'), -1)}")
    for item in list(collection_summary.get("warnings") or []):
        warnings.append(str(item))
    for item in list(collection_summary.get("errors") or []):
        errors.append(f"collection_error:{item}")

    if selected and run_meta:
        if str(run_meta.get("split") or "") != str(run_cfg.get("split") or ""):
            errors.append(f"run_meta_split_mismatch:{run_meta.get('split')}!={run_cfg.get('split')}")
        if safe_int(run_meta.get("random_seed"), -1) != safe_int(run_cfg.get("random_seed"), -2):
            errors.append("run_meta_random_seed_mismatch")
        meta_output_dir = str(run_meta.get("output_dir") or "")
        if meta_output_dir:
            try:
                if Path(meta_output_dir).resolve() != run_dir.resolve():
                    errors.append("run_meta_output_dir_mismatch")
            except Exception:
                errors.append("run_meta_output_dir_mismatch")
        else:
            warnings.append("run_meta_output_dir_missing")
    elif selected:
        errors.append("run_meta_missing_or_invalid")

    if selected and effective_config:
        if safe_int(effective_config.get("random_seed"), -1) != safe_int(run_cfg.get("random_seed"), -2):
            errors.append("effective_config_random_seed_mismatch")
        if safe_int(effective_config.get("duration_seconds"), -1) != safe_int(run_cfg.get("duration_seconds"), -2):
            errors.append("effective_config_duration_mismatch")

    status = "skipped"
    if selected:
        status = "failed" if errors else "success"

    return {
        "split": str(run_cfg.get("split") or ""),
        "duration_seconds_requested": safe_int(run_cfg.get("duration_seconds"), 0),
        "duration_seconds_source": safe_int(run_cfg.get("source_duration_seconds"), 0),
        "duration_seconds_actual": safe_int(collection_summary.get("duration_seconds_actual"), 0),
        "output_dir": relpath(run_dir, corpus_dir),
        "request_count": request_count,
        "success_count": success_count,
        "failure_count": failure_count,
        "window_count": safe_int(activity_summary.get("window_count"), len(activity_rows)),
        "activity_level_counts": activity_counts(activity_rows),
        "trace_log_size_bytes": (run_dir / "trace.log").stat().st_size if (run_dir / "trace.log").exists() else 0,
        "status": status,
        "warnings": sorted(set(warnings)),
        "errors": sorted(set(errors)),
    }


def build_split_summary(full_rows: list[dict[str, Any]], sampled_rows: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    runs_cfg = dict(config.get("runs") or {})
    for split in SPLITS:
        rows = split_rows(full_rows, split)
        sampled = split_rows(sampled_rows, split)
        configured_runs = sorted(run_id for run_id, raw in runs_cfg.items() if isinstance(raw, dict) and str(raw.get("split") or "") == split)
        payload = {
            "runs": configured_runs,
            "full_window_count": int(len(rows)),
            "activity_level_counts_full": activity_counts(rows),
        }
        if split == "train":
            payload["sampled_window_count"] = int(len(sampled_rows))
            payload["activity_level_counts_sampled"] = activity_counts(sampled_rows)
        summary[split] = payload
    return summary


def build_profile_coverage(full_rows: list[dict[str, Any]]) -> dict[str, Any]:
    per_profile: Counter[str] = Counter()
    per_role: Counter[str] = Counter()
    per_phase: Counter[str] = Counter()
    for row in full_rows:
        for profile in list(row.get("dominant_profiles") or []):
            if str(profile):
                per_profile[str(profile)] += 1
        for role in list(row.get("active_roles") or []):
            if str(role):
                per_role[str(role)] += 1
        phase = str(row.get("dominant_phase") or "")
        if phase:
            per_phase[phase] += 1
    return {
        "per_profile_window_count": dict(sorted(per_profile.items())),
        "per_role_window_count": dict(sorted(per_role.items())),
        "per_phase_window_count": dict(sorted(per_phase.items())),
    }


def build_quality_checks(
    *,
    selected: set[str],
    run_reports: dict[str, Any],
    full_rows: list[dict[str, Any]],
    sampled_rows: list[dict[str, Any]],
    no_window_activity: bool,
) -> dict[str, Any]:
    sampled_train_excludes_empty = all(str(row.get("activity_level") or "") != "empty" for row in sampled_rows)
    calibration_holdout_not_sampled = all(str(row.get("split") or "") == "train" for row in sampled_rows)
    idle_empty = sum(1 for row in full_rows if str(row.get("activity_level") or "") in {"idle", "empty"})
    nonempty = sum(1 for row in full_rows if str(row.get("activity_level") or "") != "empty")
    return {
        "all_required_runs_present": all(run_id in run_reports for run_id in DEFAULT_RUN_ORDER),
        "all_runs_have_request_events": all(
            safe_int(run_reports.get(run_id, {}).get("request_count"), 0) > 0 for run_id in selected
        ),
        "all_runs_have_window_activity": bool(no_window_activity)
        or all(safe_int(run_reports.get(run_id, {}).get("window_count"), 0) > 0 for run_id in selected),
        "sampled_train_excludes_empty": bool(sampled_train_excludes_empty),
        "calibration_holdout_not_sampled": bool(calibration_holdout_not_sampled),
        "idle_empty_fraction": float(idle_empty / len(full_rows)) if full_rows else 0.0,
        "nonempty_window_count": int(nonempty),
    }


def build_paper_stats(
    *,
    split_summary: dict[str, Any],
    full_rows: list[dict[str, Any]],
    sampled_rows: list[dict[str, Any]],
    run_reports: dict[str, Any],
) -> dict[str, Any]:
    total_full = len(full_rows)
    active_count = sum(1 for row in full_rows if str(row.get("activity_level") or "") in {"active", "burst"})
    idle_empty = sum(1 for row in full_rows if str(row.get("activity_level") or "") in {"idle", "empty"})
    total_requests = sum(safe_int(payload.get("request_count"), 0) for payload in run_reports.values())
    total_success = sum(safe_int(payload.get("success_count"), 0) for payload in run_reports.values())
    return {
        "benign_train_full_windows": safe_int(split_summary.get("train", {}).get("full_window_count"), 0),
        "benign_train_sampled_windows": int(len(sampled_rows)),
        "benign_calibration_windows": safe_int(split_summary.get("calibration", {}).get("full_window_count"), 0),
        "benign_holdout_windows": safe_int(split_summary.get("holdout", {}).get("full_window_count"), 0),
        "active_window_fraction": float(active_count / total_full) if total_full else 0.0,
        "idle_empty_window_fraction": float(idle_empty / total_full) if total_full else 0.0,
        "total_requests": int(total_requests),
        "success_rate": float(total_success / total_requests) if total_requests else 0.0,
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(Path(args.config))
    corpus_dir = normalize_corpus_dir(config, args.corpus_dir, bool(args.rehearsal))
    corpus_dir_resolved = corpus_dir.resolve()
    scale = safe_float(args.duration_scale, 1.0)
    if bool(args.rehearsal) and scale == 1.0:
        scale = 0.1
    selected = set(selected_run_ids(config, args.runs))
    run_reports: dict[str, Any] = {}
    top_warnings: list[str] = []
    top_errors: list[str] = []

    for run_id in ordered_run_ids(config):
        run_cfg = build_run_config(
            config=config,
            run_id=run_id,
            corpus_dir=corpus_dir,
            duration_scale=scale,
            skip_tracee=bool(args.allow_missing_trace),
            skip_compose_up=False,
        )
        run_report = validate_run_artifacts(
            corpus_dir=corpus_dir_resolved,
            run_id=run_id,
            selected=run_id in selected,
            run_cfg=run_cfg,
            no_window_activity=bool(args.no_window_activity),
            allow_missing_trace=bool(args.allow_missing_trace),
        )
        run_reports[run_id] = run_report
        for warning in list(run_report.get("warnings") or []):
            top_warnings.append(f"{run_id}:{warning}")
        for error in list(run_report.get("errors") or []):
            if run_id in selected:
                top_errors.append(f"{run_id}:{error}")

    full_rows = read_jsonl(corpus_dir_resolved / "full_window_index.jsonl")
    sampled_rows = read_jsonl(corpus_dir_resolved / "sampled_train_windows.jsonl")
    manifest = read_json(corpus_dir_resolved / "corpus_manifest.json")
    corpus_summary = read_json(corpus_dir_resolved / "corpus_summary.json")
    if not manifest and not bool(args.no_manifest):
        top_errors.append("missing_or_invalid_corpus_manifest")
    if not corpus_summary and not bool(args.no_manifest):
        top_errors.append("missing_or_invalid_corpus_summary")
    if any(str(row.get("split") or "") != "train" for row in sampled_rows):
        top_errors.append("sampled_train_contains_non_train_split")
    if any(str(row.get("activity_level") or "") == "empty" for row in sampled_rows):
        top_errors.append("sampled_train_contains_empty_window")

    split_summary = build_split_summary(full_rows, sampled_rows, config)
    quality_checks = build_quality_checks(
        selected=selected,
        run_reports=run_reports,
        full_rows=full_rows,
        sampled_rows=sampled_rows,
        no_window_activity=bool(args.no_window_activity),
    )
    paper_stats = build_paper_stats(
        split_summary=split_summary,
        full_rows=full_rows,
        sampled_rows=sampled_rows,
        run_reports=run_reports,
    )
    collection = dict(config.get("collection") or {})
    tracee_enabled = safe_bool(collection.get("tracee_enabled"), True) and not bool(args.allow_missing_trace)
    report = {
        "dataset": str(config.get("dataset") or "benign_corpus_v3"),
        "version": str(config.get("version") or "v3"),
        "created_at": utc_now_str(),
        "corpus_dir": display_path(corpus_dir),
        "rehearsal": bool(args.rehearsal),
        "duration_scale": float(scale),
        "window_seconds": safe_int(config.get("window_seconds"), 30),
        "time_bin_seconds": safe_int(config.get("time_bin_seconds"), 2),
        "tracee_enabled": bool(tracee_enabled),
        "runs": run_reports,
        "split_summary": split_summary,
        "profile_coverage": build_profile_coverage(full_rows),
        "quality_checks": quality_checks,
        "paper_ready_statistics": paper_stats,
        "manifest_files": {
            "full_window_index": "full_window_index.jsonl",
            "sampled_train_windows": "sampled_train_windows.jsonl",
            "corpus_manifest": "corpus_manifest.json",
            "corpus_summary": "corpus_summary.json",
            "formal_benign_collection_report": "formal_benign_collection_report.json",
        },
        "warnings": sorted(set(top_warnings)),
        "errors": sorted(set(top_errors)),
    }
    return report


def report_command(args: argparse.Namespace) -> int:
    report = build_report(args)
    config = load_config(Path(args.config))
    corpus_dir = normalize_corpus_dir(config, args.corpus_dir, bool(args.rehearsal))
    output = Path(args.output) if args.output else corpus_dir / "formal_benign_collection_report.json"
    write_json(output, report)
    if args.print_summary:
        print_summary(report)
    return 0


def fmt_counts(counts: dict[str, Any]) -> str:
    parts = [f"{level}={safe_int(counts.get(level), 0)}" for level in ACTIVITY_LEVELS if safe_int(counts.get(level), 0) > 0]
    return ", ".join(parts) if parts else "none"


def print_summary(report: dict[str, Any]) -> None:
    print("Benign Corpus v3 collection complete")
    print("")
    print("Corpus dir:")
    print(f"  {report.get('corpus_dir')}")
    print("")
    print("Runs:")
    for run_id, payload in dict(report.get("runs") or {}).items():
        output_dir = payload.get("output_dir")
        print(
            f"  {output_dir}: status={payload.get('status')} "
            f"windows={safe_int(payload.get('window_count'), 0)}, {fmt_counts(dict(payload.get('activity_level_counts') or {}))}"
        )
    split_summary = dict(report.get("split_summary") or {})
    train = dict(split_summary.get("train") or {})
    holdout = dict(split_summary.get("holdout") or {})
    sampled_counts = dict(train.get("activity_level_counts_sampled") or {})
    quality = dict(report.get("quality_checks") or {})
    print("")
    print("Train:")
    print(f"  full windows: {safe_int(train.get('full_window_count'), 0)}")
    print(f"  sampled windows: {safe_int(train.get('sampled_window_count'), 0)}")
    print(f"  empty in sampled train: {safe_int(sampled_counts.get('empty'), 0)}")
    print("")
    print("Holdout:")
    print(f"  full windows: {safe_int(holdout.get('full_window_count'), 0)}")
    print(f"  idle+empty fraction: {safe_float(quality.get('idle_empty_fraction'), 0.0):.4f}")
    print("")
    print("Artifacts:")
    for name in (
        "corpus_manifest.json",
        "corpus_summary.json",
        "sampled_train_windows.jsonl",
        "formal_benign_collection_report.json",
    ):
        print(f"  {name}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Formal benign corpus v3 config/report helpers.")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="configs/benign_corpus_v3_formal.yaml")
    common.add_argument("--corpus-dir", default="")
    common.add_argument("--runs", default="")
    common.add_argument("--duration-scale", type=float, default=1.0)
    common.add_argument("--rehearsal", action="store_true")
    common.add_argument("--skip-tracee", action="store_true")
    common.add_argument("--skip-compose-up", action="store_true")

    plan = sub.add_parser("emit-plan", parents=[common], help="Print selected run plan as TSV.")
    plan.set_defaults(func=emit_plan)

    write = sub.add_parser("write-run-config", parents=[common], help="Write one effective run config.")
    write.add_argument("--run-id", required=True)
    write.add_argument("--output", required=True)
    write.set_defaults(func=write_run_config)

    report = sub.add_parser("report", parents=[common], help="Write formal_benign_collection_report.json.")
    report.add_argument("--output", default="")
    report.add_argument("--allow-missing-trace", action="store_true")
    report.add_argument("--no-window-activity", action="store_true")
    report.add_argument("--no-manifest", action="store_true")
    report.add_argument("--print-summary", action="store_true")
    report.set_defaults(func=report_command)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(argv if argv is not None else sys.argv[1:]))
    try:
        return int(args.func(args))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
