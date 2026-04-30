#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from statistics import median
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.common.io import read_json, write_json
from src.process.window_io import load_window_graph


REQUEST_METRIC_KEYS = (
    "request_count",
    "success_count",
    "http_error_count",
    "exception_count",
    "timeout_count",
)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _read_json_if_exists(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {}
    try:
        payload = read_json(str(path))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _resolve_path(raw_path: str, *fallback_bases: Path) -> Path:
    path = Path(str(raw_path or ""))
    if path.is_absolute():
        return path
    if path.exists():
        return path
    for base in fallback_bases:
        candidate = base / path
        if candidate.exists():
            return candidate
    return path


def _quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(item) for item in values)
    idx = min(max(int(math.ceil(float(q) * len(ordered))) - 1, 0), len(ordered) - 1)
    return float(ordered[idx])


def _counter_payload() -> dict[str, int]:
    return {key: 0 for key in REQUEST_METRIC_KEYS}


def _add_counts(dst: dict[str, int], src: dict[str, Any]) -> None:
    for key in REQUEST_METRIC_KEYS:
        dst[key] = int(dst.get(key, 0)) + _safe_int(src.get(key), 0)


def _edge_type_entropy(graph: Any) -> float:
    counts: dict[str, int] = {}
    for _u, _v, _key, data in graph.edges(keys=True, data=True):
        edge_type = str((data or {}).get("type") or "UNKNOWN")
        counts[edge_type] = int(counts.get(edge_type, 0)) + 1
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        p = float(count) / float(total)
        entropy -= p * math.log2(p)
    return float(entropy)


def _window_index(path: Path) -> int:
    try:
        return int(path.stem.split("_")[-1])
    except Exception:
        return 0


def _load_window_stat(window_path: Path, root_dir: Path | None = None) -> dict[str, Any]:
    rel_path = str(window_path)
    if root_dir is not None:
        try:
            rel_path = str(window_path.relative_to(root_dir))
        except ValueError:
            rel_path = str(window_path)
    try:
        graph = load_window_graph(str(window_path))
    except Exception as exc:
        return {
            "window_file": window_path.name,
            "window_path": rel_path,
            "window_index": _window_index(window_path),
            "load_error": str(exc),
            "node_count": 0,
            "edge_count": 0,
            "process_node_count": 0,
            "edge_type_entropy": 0.0,
        }

    process_node_count = sum(1 for node_id in graph.nodes() if str(node_id).startswith("proc:"))
    return {
        "window_file": window_path.name,
        "window_path": rel_path,
        "window_index": _window_index(window_path),
        "load_error": "",
        "node_count": int(graph.number_of_nodes()),
        "edge_count": int(graph.number_of_edges()),
        "process_node_count": int(process_node_count),
        "edge_type_entropy": _edge_type_entropy(graph),
    }


def _summarize_window_stats(stats: list[dict[str, Any]]) -> dict[str, Any]:
    node_counts = [_safe_float(item.get("node_count")) for item in stats]
    edge_counts = [_safe_float(item.get("edge_count")) for item in stats]
    process_counts = [_safe_float(item.get("process_node_count")) for item in stats]
    entropies = [_safe_float(item.get("edge_type_entropy")) for item in stats]
    total = len(stats)
    edge_non_empty = sum(1 for item in stats if _safe_int(item.get("edge_count")) > 0)
    node_non_empty = sum(1 for item in stats if _safe_int(item.get("node_count")) > 0)
    scorable = sum(1 for item in stats if _safe_int(item.get("node_count")) > 0 and _safe_int(item.get("process_node_count")) > 0)
    load_errors = [item for item in stats if str(item.get("load_error") or "")]
    return {
        "window_count": int(total),
        "non_empty_window_count": int(edge_non_empty),
        "trainable_window_count": int(node_non_empty),
        "scorable_window_count": int(scorable),
        "empty_or_collapsed_window_count": int(total - edge_non_empty),
        "collapse_window_rate": (1.0 - (float(edge_non_empty) / float(total))) if total else 0.0,
        "window_load_error_count": int(len(load_errors)),
        "node_count": {
            "min": min(node_counts) if node_counts else 0.0,
            "p50": float(median(node_counts)) if node_counts else 0.0,
            "p95": _quantile(node_counts, 0.95),
            "max": max(node_counts) if node_counts else 0.0,
        },
        "edge_count": {
            "min": min(edge_counts) if edge_counts else 0.0,
            "p50": float(median(edge_counts)) if edge_counts else 0.0,
            "p95": _quantile(edge_counts, 0.95),
            "max": max(edge_counts) if edge_counts else 0.0,
        },
        "process_node_count": {
            "p50": float(median(process_counts)) if process_counts else 0.0,
            "p95": _quantile(process_counts, 0.95),
        },
        "edge_type_entropy": {
            "p50": float(median(entropies)) if entropies else 0.0,
            "p95": _quantile(entropies, 0.95),
        },
        "load_errors": [
            {"window_path": str(item.get("window_path") or ""), "error": str(item.get("load_error") or "")}
            for item in load_errors[:10]
        ],
    }


def _phase_for_offset(phases: list[dict[str, Any]], offset_seconds: float) -> dict[str, Any]:
    for phase in phases:
        start = _safe_float(phase.get("start_offset_seconds"))
        end = _safe_float(phase.get("end_offset_seconds"))
        if start <= float(offset_seconds) < end:
            return dict(phase)
    return {}


def _increment(mapping: dict[str, int], key: str, amount: int = 1) -> None:
    label = str(key or "unknown")
    mapping[label] = int(mapping.get(label, 0)) + int(amount)


def _collect_driver_metrics(run_meta: dict[str, Any], run_dir: Path) -> dict[str, int]:
    out = _counter_payload()
    metrics_path_raw = str(run_meta.get("driver_metrics") or "")
    if not metrics_path_raw:
        _add_counts(out, dict(run_meta.get("driver_metrics_summary") or {}))
        return out
    metrics_path = _resolve_path(metrics_path_raw, run_dir, ROOT_DIR)
    payload = _read_json_if_exists(metrics_path)
    _add_counts(out, dict(payload.get("aggregate") or run_meta.get("driver_metrics_summary") or {}))
    return out


def _request_metric_summary(metrics: dict[str, int]) -> dict[str, Any]:
    request_count = _safe_int(metrics.get("request_count"))
    success_count = _safe_int(metrics.get("success_count"))
    http_errors = _safe_int(metrics.get("http_error_count"))
    exceptions = _safe_int(metrics.get("exception_count"))
    return {
        **{key: _safe_int(metrics.get(key)) for key in REQUEST_METRIC_KEYS},
        "error_count": int(http_errors + exceptions),
        "success_rate": (float(success_count) / float(request_count)) if request_count else 0.0,
        "error_rate": (float(http_errors + exceptions) / float(request_count)) if request_count else 0.0,
    }


def _load_benign_run_metas(corpus_dir: Path) -> dict[str, dict[str, Any]]:
    metas: dict[str, dict[str, Any]] = {}
    if not corpus_dir.exists():
        return metas
    for run_meta_path in sorted(corpus_dir.glob("*/run_meta.json")):
        run_meta = _read_json_if_exists(run_meta_path)
        run_id = str(run_meta.get("run_id") or run_meta_path.parent.name)
        metas[run_id] = {"run_meta": run_meta, "run_dir": run_meta_path.parent}
    return metas


def _manifest_window_records(windows_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    manifest_path = windows_dir / "gmae_windows_manifest.json"
    manifest = _read_json_if_exists(manifest_path)
    records: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for raw in list(manifest.get("records") or []):
        if not isinstance(raw, dict):
            continue
        raw_path = str(raw.get("path") or "")
        window_id = str(raw.get("window_id") or "").strip()
        candidates = []
        if raw_path:
            candidates.append(_resolve_path(raw_path, windows_dir, ROOT_DIR))
        if window_id:
            candidates.append(windows_dir / f"{window_id}.json")
        if not candidates:
            continue
        path = next((candidate for candidate in candidates if candidate.exists()), candidates[0])
        if str(path) == "":
            continue
        key = str(path.resolve()) if path.exists() else str(path)
        seen_paths.add(key)
        records.append(
            {
                "path": path,
                "source_run_id": str(raw.get("source_run_id") or ""),
                "split_role": str(raw.get("split_role") or ""),
                "source_profile": str(raw.get("source_profile") or ""),
                "source_phase_id": str(raw.get("source_phase_id") or ""),
                "window_sequence": _safe_int(raw.get("window_sequence")),
            }
        )

    for path in sorted(windows_dir.glob("window_*.json")) if windows_dir.exists() else []:
        key = str(path.resolve())
        if key in seen_paths:
            continue
        records.append(
            {
                "path": path,
                "source_run_id": "",
                "split_role": "",
                "source_profile": "",
                "source_phase_id": "",
                "window_sequence": _window_index(path),
            }
        )
    return records, manifest


def _fallback_corpus_window_records(corpus_dir: Path, run_metas: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not corpus_dir.exists():
        return records
    for run_id, payload in sorted(run_metas.items()):
        run_meta = dict(payload.get("run_meta") or {})
        run_dir = Path(payload.get("run_dir") or corpus_dir / run_id)
        window_dirs = sorted(path for path in run_dir.glob("windows*") if path.is_dir())
        for window_dir in window_dirs:
            for window_path in sorted(window_dir.glob("window_*.json")):
                sequence = _window_index(window_path)
                offset = float(max(sequence - 1, 0)) * _safe_float(run_meta.get("window_seconds"), 30.0)
                phase = _phase_for_offset(list(run_meta.get("phases") or []), offset)
                records.append(
                    {
                        "path": window_path,
                        "source_run_id": run_id,
                        "split_role": str(run_meta.get("split_role") or ""),
                        "source_profile": str(phase.get("profile_id") or ""),
                        "source_phase_id": str(phase.get("phase_id") or ""),
                        "window_sequence": int(sequence),
                    }
                )
    return records


def _generic_window_records(windows_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not windows_dir.exists():
        return records
    for path in sorted(windows_dir.rglob("window_*.json")):
        records.append(
            {
                "path": path,
                "source_run_id": "",
                "split_role": "",
                "source_profile": "",
                "source_phase_id": "",
                "window_sequence": _window_index(path),
            }
        )
    return records


def _dedupe_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        path = Path(record.get("path") or "")
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return deduped


def _summarize_distributions(records: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    by_split: dict[str, int] = {}
    by_profile: dict[str, int] = {}
    by_run: dict[str, int] = {}
    for record in records:
        _increment(by_split, str(record.get("split_role") or "unknown"))
        _increment(by_profile, str(record.get("source_profile") or "unknown"))
        _increment(by_run, str(record.get("source_run_id") or "unknown"))
    return {
        "by_split_role": dict(sorted(by_split.items())),
        "by_profile": dict(sorted(by_profile.items())),
        "by_run_id": dict(sorted(by_run.items())),
    }


def inspect_benign(corpus_dir: Path, windows_dir: Path, window_seconds: int) -> dict[str, Any]:
    run_metas = _load_benign_run_metas(corpus_dir)
    manifest_records: list[dict[str, Any]] = []
    manifest: dict[str, Any] = {}
    if windows_dir.exists():
        manifest_records, manifest = _manifest_window_records(windows_dir)

    window_records = manifest_records
    if not window_records:
        window_records = _fallback_corpus_window_records(corpus_dir, run_metas)
    if not window_records and windows_dir.exists():
        window_records = _generic_window_records(windows_dir)
    window_records = _dedupe_records(window_records)

    stats: list[dict[str, Any]] = []
    for record in window_records:
        path = Path(record.get("path") or "")
        if not path.exists():
            continue
        item = _load_window_stat(path, windows_dir if windows_dir.exists() else corpus_dir)
        item.update(
            {
                "source_run_id": str(record.get("source_run_id") or ""),
                "split_role": str(record.get("split_role") or ""),
                "source_profile": str(record.get("source_profile") or ""),
                "source_phase_id": str(record.get("source_phase_id") or ""),
                "window_sequence": _safe_int(record.get("window_sequence")),
            }
        )
        stats.append(item)

    request_metrics = _counter_payload()
    run_summaries: list[dict[str, Any]] = []
    observed_duration_seconds = 0
    for run_id, payload in sorted(run_metas.items()):
        run_meta = dict(payload.get("run_meta") or {})
        run_dir = Path(payload.get("run_dir") or corpus_dir / run_id)
        observed_duration_seconds += _safe_int(run_meta.get("duration_seconds"))
        run_stats = [item for item in stats if str(item.get("source_run_id") or "") == run_id]
        _add_counts(request_metrics, _collect_driver_metrics(run_meta, run_dir))
        run_summaries.append(
            {
                "run_id": run_id,
                "split_role": str(run_meta.get("split_role") or ""),
                "duration_seconds": _safe_int(run_meta.get("duration_seconds")),
                "driver_metrics": str(run_meta.get("driver_metrics") or ""),
                "window_count": int(len(run_stats)),
                "non_empty_window_count": int(sum(1 for item in run_stats if _safe_int(item.get("edge_count")) > 0)),
            }
        )

    graph_summary = _summarize_window_stats(stats)
    manifest_summary = dict(manifest.get("summary") or {})
    return {
        "pilot_type": "benign",
        "inputs": {
            "corpus_dir": str(corpus_dir),
            "windows_dir": str(windows_dir),
            "corpus_dir_exists": bool(corpus_dir.exists()),
            "windows_dir_exists": bool(windows_dir.exists()),
            "manifest_path": str(windows_dir / "gmae_windows_manifest.json"),
            "manifest_present": bool(manifest),
        },
        "pilot_minimum": {
            "duration_seconds": 3600,
            "min_non_empty_windows_at_30s": 120,
        },
        "observed_duration_seconds": int(observed_duration_seconds),
        "total_window_count": int(graph_summary["window_count"]),
        "non_empty_window_count": int(graph_summary["non_empty_window_count"]),
        "collapse_window_rate": float(graph_summary["collapse_window_rate"]),
        "window_graph_summary": graph_summary,
        "manifest_summary": manifest_summary,
        "window_distribution": _summarize_distributions(stats),
        "request_success_error_metrics": _request_metric_summary(request_metrics),
        "runs": run_summaries,
    }


def _metric_by_stage(metrics: dict[str, Any], stage: str) -> dict[str, Any]:
    by_stage = dict(metrics.get("by_stage") or {})
    return dict(by_stage.get(stage) or {})


def _extract_run_stage_summary(run_meta_path: Path, benchmark_dir: Path) -> dict[str, Any]:
    run_meta = _read_json_if_exists(run_meta_path)
    if str(run_meta.get("kind") or "") != "attack":
        return {}
    run_dir = run_meta_path.parent
    metrics_path_raw = str(run_meta.get("metrics_path") or "")
    metrics_path = _resolve_path(metrics_path_raw, run_dir, ROOT_DIR) if metrics_path_raw else run_dir / "metrics.json"
    metrics = _read_json_if_exists(metrics_path)
    by_stage = dict(metrics.get("by_stage") or {})
    warmup_mean = _safe_float(_metric_by_stage(metrics, "warmup").get("mean_score"))
    attack_mean = _safe_float(_metric_by_stage(metrics, "attack").get("mean_score"))
    cooldown_mean = _safe_float(_metric_by_stage(metrics, "cooldown").get("mean_score"))
    transition_count = _safe_int(_metric_by_stage(metrics, "transition").get("sample_count"))
    family_id = str(run_meta.get("family_id") or run_meta.get("scenario_id") or "")
    try:
        run_id = str(run_dir.relative_to(benchmark_dir))
    except ValueError:
        run_id = run_dir.name
    return {
        "run_id": run_id,
        "scenario_id": str(run_meta.get("scenario_id") or ""),
        "family_id": family_id,
        "benchmark_split": str(run_meta.get("benchmark_split") or ""),
        "repeat_id": _safe_int(run_meta.get("repeat_id")),
        "variant_id": str(run_meta.get("variant_id") or ""),
        "command_template_id": str(run_meta.get("command_template_id") or ""),
        "parameters": dict(run_meta.get("parameters") or {}),
        "metrics_path": str(metrics_path),
        "metrics_present": bool(metrics),
        "stage_metrics_present": bool(by_stage),
        "window_count": _safe_int(metrics.get("window_count")),
        "attack_mean_score": attack_mean,
        "warmup_mean_score": warmup_mean,
        "cooldown_mean_score": cooldown_mean,
        "attack_stage_score_gt_warmup_cooldown": bool(metrics and attack_mean > max(warmup_mean, cooldown_mean)),
        "attack_score_gap_vs_max_context": float(attack_mean - max(warmup_mean, cooldown_mean)),
        "transition_window_count": transition_count,
        "stage_labels_present": sorted(str(key) for key in by_stage.keys()),
        "scenario_level_recall": _safe_float(metrics.get("scenario_level_recall")),
        "window_level_recall": _safe_float(metrics.get("window_level_recall")),
    }


def _collect_attack_window_stats(benchmark_dir: Path, benchmark_windows_dir: Path) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    if benchmark_windows_dir.exists():
        records = _generic_window_records(benchmark_windows_dir)
    if not records and benchmark_dir.exists():
        for windows_path in sorted(benchmark_dir.rglob("windows")):
            if windows_path.is_dir():
                records.extend(_generic_window_records(windows_path))
    records = _dedupe_records(records)
    stats = [
        _load_window_stat(Path(record.get("path") or ""), benchmark_windows_dir if benchmark_windows_dir.exists() else benchmark_dir)
        for record in records
        if Path(record.get("path") or "").exists()
    ]
    return _summarize_window_stats(stats)


def inspect_attack(benchmark_dir: Path, benchmark_windows_dir: Path) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    families: set[str] = set()
    if benchmark_dir.exists():
        for run_meta_path in sorted(benchmark_dir.rglob("run_meta.json")):
            run_summary = _extract_run_stage_summary(run_meta_path, benchmark_dir)
            if not run_summary:
                continue
            runs.append(run_summary)
            if run_summary.get("family_id"):
                families.add(str(run_summary["family_id"]))

    scored_runs = [run for run in runs if bool(run.get("stage_metrics_present"))]
    separated_runs = [run for run in scored_runs if bool(run.get("attack_stage_score_gt_warmup_cooldown"))]
    transition_counts = [_safe_int(run.get("transition_window_count")) for run in scored_runs]
    return {
        "pilot_type": "attack",
        "inputs": {
            "benchmark_dir": str(benchmark_dir),
            "benchmark_windows_dir": str(benchmark_windows_dir),
            "benchmark_dir_exists": bool(benchmark_dir.exists()),
            "benchmark_windows_dir_exists": bool(benchmark_windows_dir.exists()),
        },
        "pilot_minimum": {"min_attack_families": 3},
        "attack_family_count": int(len(families)),
        "run_count": int(len(runs)),
        "scored_run_count": int(len(scored_runs)),
        "attack_score_separation": {
            "separated_run_count": int(len(separated_runs)),
            "scored_run_count": int(len(scored_runs)),
            "separated_run_rate": (float(len(separated_runs)) / float(len(scored_runs))) if scored_runs else 0.0,
        },
        "transition_window_count": {
            "total": int(sum(transition_counts)),
            "p50": float(median(transition_counts)) if transition_counts else 0.0,
            "p95": _quantile([float(item) for item in transition_counts], 0.95),
            "max": max(transition_counts) if transition_counts else 0,
        },
        "window_graph_summary": _collect_attack_window_stats(benchmark_dir, benchmark_windows_dir),
        "runs": runs,
    }


def _collect_benign_holdout_metrics(benchmark_dir: Path, corpus_dir: Path) -> dict[str, Any]:
    candidates: list[Path] = []
    if benchmark_dir.exists():
        candidates.extend(sorted((benchmark_dir / "benign_holdout").glob("*.json")))
        candidates.extend(sorted(benchmark_dir.rglob("*holdout*metrics*.json")))
    if corpus_dir.exists():
        candidates.extend(sorted(corpus_dir.rglob("*holdout*metrics*.json")))

    summaries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        payload = _read_json_if_exists(path)
        if str(payload.get("metric_type") or "") != "benign_holdout":
            continue
        summaries.append(
            {
                "path": str(path),
                "run_id": str(payload.get("run_id") or ""),
                "split_role": str(payload.get("split_role") or ""),
                "threshold": _safe_float(payload.get("threshold")),
                "duration_seconds": _safe_int(payload.get("duration_seconds")),
                "total_windows": _safe_int(payload.get("total_windows")),
                "false_positive_windows": _safe_int(payload.get("false_positive_windows")),
                "false_positive_rate": _safe_float(payload.get("false_positive_rate")),
                "false_alarms_per_hour": _safe_float(payload.get("false_alarms_per_hour")),
                "alerts_per_minute": _safe_float(payload.get("alerts_per_minute")),
            }
        )

    total_windows = sum(_safe_int(item.get("total_windows")) for item in summaries)
    false_positive_windows = sum(_safe_int(item.get("false_positive_windows")) for item in summaries)
    duration_seconds = sum(_safe_int(item.get("duration_seconds")) for item in summaries)
    return {
        "metric_type": "benign_holdout_collection",
        "run_count": int(len(summaries)),
        "total_windows": int(total_windows),
        "false_positive_windows": int(false_positive_windows),
        "false_positive_rate": (float(false_positive_windows) / float(total_windows)) if total_windows else 0.0,
        "duration_seconds": int(duration_seconds),
        "false_alarms_per_hour": (
            float(false_positive_windows) / max(float(duration_seconds) / 3600.0, 1e-9)
            if duration_seconds > 0
            else 0.0
        ),
        "runs": summaries,
    }


def _check(name: str, status: str, observed: Any, target: Any, detail: str = "") -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "observed": observed,
        "target": target,
        "detail": detail,
    }


def build_checks(summary: dict[str, Any], window_seconds: int) -> list[dict[str, Any]]:
    benign = dict(summary.get("benign") or {})
    attack = dict(summary.get("attack") or {})
    holdout = dict(summary.get("benign_holdout") or {})
    checks: list[dict[str, Any]] = []

    duration = _safe_int(benign.get("observed_duration_seconds"))
    checks.append(
        _check(
            "benign_pilot_duration",
            "pass" if duration >= 3600 else ("missing" if duration == 0 else "fail"),
            duration,
            ">= 3600 seconds",
        )
    )

    non_empty = _safe_int(benign.get("non_empty_window_count"))
    min_non_empty = 120 if int(window_seconds) == 30 else int(math.ceil(3600.0 / max(float(window_seconds), 1.0)))
    checks.append(
        _check(
            "benign_non_empty_windows",
            "pass" if non_empty >= min_non_empty else ("missing" if non_empty == 0 else "fail"),
            non_empty,
            f">= {min_non_empty}",
        )
    )

    collapse_rate = _safe_float(benign.get("collapse_window_rate"))
    graph_summary = dict(benign.get("window_graph_summary") or {})
    edge_p50 = _safe_float((graph_summary.get("edge_count") or {}).get("p50"))
    if _safe_int(graph_summary.get("window_count")) == 0:
        collapse_status = "missing"
    elif non_empty == 0 or edge_p50 <= 0.0:
        collapse_status = "fail"
    elif collapse_rate > 0.25:
        collapse_status = "warn"
    else:
        collapse_status = "pass"
    checks.append(
        _check(
            "reduction_not_collapsed",
            collapse_status,
            {"collapse_window_rate": collapse_rate, "edge_count_p50": edge_p50},
            "non-empty windows present, edge_count p50 > 0, collapse rate preferably <= 0.25",
        )
    )

    request_metrics = dict(benign.get("request_success_error_metrics") or {})
    request_count = _safe_int(request_metrics.get("request_count"))
    success_rate = _safe_float(request_metrics.get("success_rate"))
    if request_count == 0:
        request_status = "missing"
    elif success_rate < 0.8:
        request_status = "warn"
    else:
        request_status = "pass"
    checks.append(
        _check(
            "driver_request_metrics_present",
            request_status,
            {"request_count": request_count, "success_rate": success_rate, "error_rate": _safe_float(request_metrics.get("error_rate"))},
            "request_count > 0 and success_rate >= 0.8",
        )
    )

    family_count = _safe_int(attack.get("attack_family_count"))
    checks.append(
        _check(
            "attack_family_coverage",
            "pass" if family_count >= 3 else ("missing" if family_count == 0 else "fail"),
            family_count,
            ">= 3 families",
        )
    )

    separation = dict(attack.get("attack_score_separation") or {})
    scored_runs = _safe_int(separation.get("scored_run_count"))
    separated_runs = _safe_int(separation.get("separated_run_count"))
    if scored_runs == 0:
        separation_status = "missing"
    elif separated_runs == scored_runs:
        separation_status = "pass"
    elif separated_runs > 0:
        separation_status = "warn"
    else:
        separation_status = "fail"
    checks.append(
        _check(
            "attack_stage_scores_above_context",
            separation_status,
            separation,
            "attack mean score > max(warmup mean, cooldown mean) for each scored run",
        )
    )

    transition = dict(attack.get("transition_window_count") or {})
    transition_max = _safe_int(transition.get("max"))
    if scored_runs == 0:
        transition_status = "missing"
    elif transition_max <= 2:
        transition_status = "pass"
    elif transition_max <= 4:
        transition_status = "warn"
    else:
        transition_status = "fail"
    checks.append(
        _check(
            "transition_window_count_reasonable",
            transition_status,
            transition,
            "max transition windows per scored run <= 2 preferred, <= 4 tolerated",
        )
    )

    holdout_runs = _safe_int(holdout.get("run_count"))
    fpr = _safe_float(holdout.get("false_positive_rate"))
    checks.append(
        _check(
            "benign_holdout_fpr",
            "pass" if holdout_runs and fpr < 0.05 else ("missing" if not holdout_runs else "fail"),
            {"run_count": holdout_runs, "false_positive_rate": fpr},
            "< 0.05",
        )
    )

    false_alarms_per_hour = _safe_float(holdout.get("false_alarms_per_hour"))
    max_false_alarms_per_hour = (3600.0 / max(float(window_seconds), 1.0)) * 0.05
    checks.append(
        _check(
            "benign_false_alarms_per_hour",
            "pass" if holdout_runs and false_alarms_per_hour <= max_false_alarms_per_hour else ("missing" if not holdout_runs else "warn"),
            false_alarms_per_hour,
            f"<= {max_false_alarms_per_hour:.3f} per hour, derived from 5% FPR at {int(window_seconds)}s windows",
        )
    )

    return checks


def inspect_dataset(args: argparse.Namespace) -> dict[str, Any]:
    benign_corpus_dir = Path(str(args.benign_corpus_dir))
    benign_windows_dir = Path(str(args.benign_windows_dir))
    benchmark_dir = Path(str(args.benchmark_dir or args.benchmark_root))
    benchmark_windows_dir = Path(str(args.benchmark_windows_dir))
    window_seconds = int(args.window_seconds)

    summary: dict[str, Any] = {
        "schema_version": 2,
        "metric_type": "drsec_v3_dataset_pilot_summary",
        "inputs": {
            "benign_corpus_dir": str(benign_corpus_dir),
            "benign_windows_dir": str(benign_windows_dir),
            "benchmark_dir": str(benchmark_dir),
            "benchmark_windows_dir": str(benchmark_windows_dir),
            "window_seconds": int(window_seconds),
        },
        "benign": inspect_benign(benign_corpus_dir, benign_windows_dir, window_seconds),
        "attack": inspect_attack(benchmark_dir, benchmark_windows_dir),
        "benign_holdout": _collect_benign_holdout_metrics(benchmark_dir, benign_corpus_dir),
    }
    checks = build_checks(summary, window_seconds)
    summary["checks"] = checks
    summary["check_status_counts"] = {
        status: int(sum(1 for item in checks if str(item.get("status") or "") == status))
        for status in ("pass", "warn", "fail", "missing")
    }
    summary["unclosed_items"] = [
        item for item in checks if str(item.get("status") or "") in {"fail", "missing"}
    ]
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign-corpus-dir", default="data/benign_corpus_v3")
    ap.add_argument("--benign-windows-dir", default="data/processed/benign_windows_v3")
    ap.add_argument("--benchmark-dir", default="")
    ap.add_argument("--benchmark-root", default="data/benchmarks_v3")
    ap.add_argument("--benchmark-windows-dir", default="data/processed/benchmark_windows_v3")
    ap.add_argument("--window-seconds", type=int, default=30)
    ap.add_argument("--out-json", default="")
    ap.add_argument("--output-json", default="")
    args = ap.parse_args()

    summary = inspect_dataset(args)
    output_json = str(args.out_json or args.output_json or "")
    if output_json:
        write_json(output_json, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
