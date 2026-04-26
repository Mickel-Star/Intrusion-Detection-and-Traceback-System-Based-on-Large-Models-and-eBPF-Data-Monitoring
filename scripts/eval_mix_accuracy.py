#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.analysis.report_generator import AnalysisEngine
from src.common.benchmarking import (
    ALLOWED_ROLES,
    DEFAULT_SWEEP_THRESHOLDS,
    DEFAULT_THRESHOLD,
    IGNORED_LABEL,
    NEGATIVE_LABEL,
    POSITIVE_LABEL,
    normalize_container_id,
    role_label,
    short_container_id,
    validate_labels_payload,
)
from src.common.io import read_json, write_json
from src.process.window_io import load_window_graph


@dataclass(frozen=True)
class RunArtifacts:
    run_id: str
    run_dir: Path
    windows_dir: Path
    scenario_id: str
    repeat_id: int
    kind: str
    labels_path: Optional[Path]
    run_meta_path: Optional[Path]


def load_run_meta(path: str | Path | None) -> Dict[str, Any]:
    if not path:
        return {}
    meta_path = Path(path)
    if not meta_path.exists():
        return {}
    return read_json(str(meta_path)) or {}


def iter_window_files(windows_dir: str | Path, limit: int = 0) -> List[Path]:
    paths = sorted(Path(windows_dir).glob("window_*.json"))
    if limit and limit > 0:
        paths = paths[: int(limit)]
    return paths


def proc_nodes(g) -> List[tuple[str, Dict[str, Any]]]:
    out = []
    for node_id, data in g.nodes(data=True):
        if isinstance(node_id, str) and node_id.startswith("proc:"):
            out.append((node_id, (data or {}).get("meta", {}) or {}))
    return out


def compute_metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, float | int]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    acc = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": acc,
        "support": tp + fp + fn + tn,
        "positive_support": tp + fn,
        "negative_support": fp + tn,
    }


def _match_container_record(container_id: str, containers: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    needle = short_container_id(container_id)
    if not needle:
        return None
    for record in containers:
        candidate = short_container_id(record.get("container_id") or "")
        if not candidate:
            continue
        if needle == candidate or needle.startswith(candidate) or candidate.startswith(needle):
            return record
    return None


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _infer_repeat_id(run_dir: Path, run_meta: Dict[str, Any]) -> int:
    repeat_id = _safe_int(run_meta.get("repeat_id"))
    if repeat_id > 0:
        return repeat_id
    match = re.search(r"(\d+)$", run_dir.name)
    if match:
        return int(match.group(1))
    return 1


def _legacy_labels_from_run_meta(run_meta: Dict[str, Any], scenario_id: str, kind: str) -> Dict[str, Any]:
    positive_roles = ["attacker"] if run_meta.get("attacker_container_id") else []
    negative_roles = ["benign"] if run_meta.get("benign_container_id") else []
    containers = []
    role_fields = {
        "attacker": "attacker_container_id",
        "benign": "benign_container_id",
        "target": "target_container_id",
        "target_dsock": "target_dsock_container_id",
        "c2": "c2_container_id",
    }
    for role, field in role_fields.items():
        container_id = normalize_container_id(run_meta.get(field) or "")
        if not container_id:
            continue
        containers.append(
            {
                "role": role,
                "container_id": container_id,
                "container_name": "",
                "label": role_label(role, positive_roles, negative_roles),
            }
        )
    return validate_labels_payload(
        {
            "schema_version": 1,
            "scenario_id": scenario_id,
            "kind": kind,
            "positive_roles": positive_roles,
            "negative_roles": negative_roles,
            "containers": containers,
        }
    )


def load_labels_for_run(run: RunArtifacts) -> Dict[str, Any]:
    if run.labels_path and run.labels_path.exists():
        return validate_labels_payload(read_json(str(run.labels_path)) or {})
    run_meta = load_run_meta(run.run_meta_path)
    return _legacy_labels_from_run_meta(run_meta, run.scenario_id, run.kind)


def collect_benchmark_runs(benchmark_root: str | Path) -> List[RunArtifacts]:
    root = Path(benchmark_root)
    if not root.exists():
        raise FileNotFoundError(f"benchmark root not found: {root}")

    runs: List[RunArtifacts] = []
    for windows_dir in sorted(root.rglob("windows")):
        run_dir = windows_dir.parent
        labels_path = run_dir / "labels.json"
        run_meta_path = run_dir / "run_meta.json"
        if not labels_path.exists() and not run_meta_path.exists():
            continue
        run_meta = load_run_meta(run_meta_path)
        scenario_id = str(run_meta.get("scenario_id") or run_dir.parent.name).strip() or run_dir.parent.name
        repeat_id = _infer_repeat_id(run_dir, run_meta)
        kind = str(run_meta.get("kind") or "").strip().lower()
        if not kind and labels_path.exists():
            kind = str((read_json(str(labels_path)) or {}).get("kind") or "").strip().lower()
        kind = kind or "unknown"
        runs.append(
            RunArtifacts(
                run_id=str(run_dir.relative_to(root)),
                run_dir=run_dir,
                windows_dir=windows_dir,
                scenario_id=scenario_id,
                repeat_id=repeat_id,
                kind=kind,
                labels_path=labels_path if labels_path.exists() else None,
                run_meta_path=run_meta_path if run_meta_path.exists() else None,
            )
        )
    return runs


def _empty_dataset(runs: Sequence[RunArtifacts]) -> Dict[str, Any]:
    return {
        "runs": [
            {
                "run_id": run.run_id,
                "scenario_id": run.scenario_id,
                "repeat_id": run.repeat_id,
                "kind": run.kind,
                "run_dir": str(run.run_dir),
            }
            for run in runs
        ],
        "process_samples": [],
        "window_samples": [],
        "role_samples": [],
        "scenario_samples": [],
        "run_debug": {},
    }


def build_run_samples(
    run: RunArtifacts,
    engine: AnalysisEngine,
    limit: int = 0,
    include_debug: bool = False,
) -> Dict[str, Any]:
    labels = load_labels_for_run(run)
    containers = [c for c in labels.get("containers", []) if c.get("label") in {POSITIVE_LABEL, NEGATIVE_LABEL}]
    process_truth: Dict[str, Dict[str, Any]] = {}
    window_samples: List[Dict[str, Any]] = []
    debug_windows: List[Dict[str, Any]] = []

    for window_file in iter_window_files(run.windows_dir, limit=limit):
        graph = load_window_graph(str(window_file))
        window_pos_keys = set()
        window_neg_keys = set()
        window_scores: Dict[str, float] = {}

        for _, meta in proc_nodes(graph):
            pid = _safe_int(meta.get("pid"))
            container_record = _match_container_record(meta.get("container_id") or "", containers)
            if not pid or not container_record:
                continue
            label = str(container_record.get("label") or "")
            if label not in {POSITIVE_LABEL, NEGATIVE_LABEL}:
                continue
            container_short = short_container_id(container_record.get("container_id") or "")
            proc_key = f"{run.run_id}:{container_short}:{pid}"
            process_truth.setdefault(
                proc_key,
                {
                    "sample_id": proc_key,
                    "run_id": run.run_id,
                    "scenario_id": run.scenario_id,
                    "repeat_id": run.repeat_id,
                    "kind": run.kind,
                    "role": str(container_record.get("role") or ""),
                    "container_id": container_short,
                    "label": label,
                    "pid": pid,
                    "process_name": str(meta.get("name") or meta.get("pathname") or "unknown"),
                    "score": 0.0,
                },
            )
            if label == POSITIVE_LABEL:
                window_pos_keys.add(proc_key)
            else:
                window_neg_keys.add(proc_key)

        window_alerts = engine.detect_window_alerts_in_window(graph, threshold=0.0, window_hint=window_file.name)
        alert = window_alerts[0] if window_alerts else None
        candidates = engine.detect_suspicious_processes_in_window(graph, threshold=0.0, window_hint=window_file.name)
        candidate_debug: List[Dict[str, Any]] = []
        for item in candidates or []:
            meta = item.get("process_meta", {}) or {}
            pid = _safe_int(meta.get("pid"))
            container_record = _match_container_record(meta.get("container_id") or "", containers)
            if not pid or not container_record:
                continue
            label = str(container_record.get("label") or "")
            if label not in {POSITIVE_LABEL, NEGATIVE_LABEL}:
                continue
            container_short = short_container_id(container_record.get("container_id") or "")
            proc_key = f"{run.run_id}:{container_short}:{pid}"
            score = float(item.get("process_score", item.get("rarity_score", 0.0)) or 0.0)
            process_truth.setdefault(
                proc_key,
                {
                    "sample_id": proc_key,
                    "run_id": run.run_id,
                    "scenario_id": run.scenario_id,
                    "repeat_id": run.repeat_id,
                    "kind": run.kind,
                    "role": str(container_record.get("role") or ""),
                    "container_id": container_short,
                    "label": label,
                    "pid": pid,
                    "process_name": str(meta.get("name") or meta.get("pathname") or "unknown"),
                    "score": 0.0,
                },
            )
            process_truth[proc_key]["score"] = max(float(process_truth[proc_key].get("score", 0.0)), score)
            window_scores[proc_key] = max(float(window_scores.get(proc_key, 0.0)), score)
            if include_debug:
                candidate_debug.append(
                    {
                        "pid": pid,
                        "role": str(container_record.get("role") or ""),
                        "label": label,
                        "score": score,
                        "name": str(meta.get("name") or meta.get("pathname") or "unknown"),
                    }
                )

        window_label = ""
        relevant_keys = set()
        if window_pos_keys:
            window_label = POSITIVE_LABEL
            relevant_keys = window_pos_keys
        elif window_neg_keys:
            window_label = NEGATIVE_LABEL
            relevant_keys = window_neg_keys

        if window_label:
            window_score = float(alert.window_score) if alert is not None else max((float(window_scores.get(key, 0.0)) for key in relevant_keys), default=0.0)
            window_samples.append(
                {
                    "sample_id": f"{run.run_id}:{window_file.name}",
                    "run_id": run.run_id,
                    "scenario_id": run.scenario_id,
                    "repeat_id": run.repeat_id,
                    "kind": run.kind,
                    "window_file": window_file.name,
                    "label": window_label,
                    "score": window_score,
                    "alerted": bool(alert is not None),
                }
            )

        if include_debug:
            debug_windows.append(
                {
                    "window_file": window_file.name,
                    "window_alert": alert.to_dict() if alert is not None else None,
                    "ground_truth_positive": sorted(list(window_pos_keys)),
                    "ground_truth_negative": sorted(list(window_neg_keys)),
                    "candidate_processes": sorted(candidate_debug, key=lambda item: float(item.get("score", 0.0)), reverse=True),
                }
            )

    process_samples = sorted(process_truth.values(), key=lambda item: (item["run_id"], item["container_id"], item["pid"]))
    role_best_scores: Dict[str, float] = {}
    for item in process_samples:
        role_key = f"{item['run_id']}:{item['role']}:{item['container_id']}"
        role_best_scores[role_key] = max(float(role_best_scores.get(role_key, 0.0)), float(item.get("score", 0.0)))

    role_samples: List[Dict[str, Any]] = []
    for container in containers:
        container_short = short_container_id(container.get("container_id") or "")
        if not container_short:
            continue
        label = str(container.get("label") or "")
        if label not in {POSITIVE_LABEL, NEGATIVE_LABEL}:
            continue
        role_name = str(container.get("role") or "")
        role_key = f"{run.run_id}:{role_name}:{container_short}"
        role_samples.append(
            {
                "sample_id": role_key,
                "run_id": run.run_id,
                "scenario_id": run.scenario_id,
                "repeat_id": run.repeat_id,
                "kind": run.kind,
                "role": role_name,
                "container_id": container_short,
                "label": label,
                "score": float(role_best_scores.get(role_key, 0.0)),
            }
        )

    pos_role_scores = [float(item.get("score", 0.0)) for item in role_samples if item.get("label") == POSITIVE_LABEL]
    neg_role_scores = [float(item.get("score", 0.0)) for item in role_samples if item.get("label") == NEGATIVE_LABEL]
    scenario_samples: List[Dict[str, Any]] = []
    if pos_role_scores:
        scenario_samples.append(
            {
                "sample_id": run.run_id,
                "run_id": run.run_id,
                "scenario_id": run.scenario_id,
                "repeat_id": run.repeat_id,
                "kind": run.kind,
                "label": POSITIVE_LABEL,
                "score": max(pos_role_scores),
            }
        )
    elif neg_role_scores:
        scenario_samples.append(
            {
                "sample_id": run.run_id,
                "run_id": run.run_id,
                "scenario_id": run.scenario_id,
                "repeat_id": run.repeat_id,
                "kind": run.kind,
                "label": NEGATIVE_LABEL,
                "score": max(neg_role_scores),
            }
        )

    run_debug = {
        "run_id": run.run_id,
        "scenario_id": run.scenario_id,
        "repeat_id": run.repeat_id,
        "kind": run.kind,
        "labels": labels,
        "window_candidates": debug_windows,
        "process_samples": process_samples,
        "role_samples": role_samples,
        "scenario_samples": scenario_samples,
    }

    return {
        "process_samples": process_samples,
        "window_samples": window_samples,
        "role_samples": role_samples,
        "scenario_samples": scenario_samples,
        "run_debug": run_debug,
    }


def build_dataset(
    runs: Sequence[RunArtifacts],
    engine: Optional[AnalysisEngine] = None,
    limit: int = 0,
    include_debug: bool = False,
) -> Dict[str, Any]:
    dataset = _empty_dataset(runs)
    shared_engine = engine or AnalysisEngine()
    for run in runs:
        run_data = build_run_samples(run, shared_engine, limit=limit, include_debug=include_debug)
        for key in ("process_samples", "window_samples", "role_samples", "scenario_samples"):
            dataset[key].extend(run_data[key])
        if include_debug:
            dataset["run_debug"][run.run_id] = run_data["run_debug"]
    return dataset


def _summarize_samples(samples: Iterable[Dict[str, Any]], threshold: float) -> Dict[str, Any]:
    tp = fp = fn = tn = 0
    for sample in samples:
        label = str(sample.get("label") or "")
        if label not in {POSITIVE_LABEL, NEGATIVE_LABEL}:
            continue
        pred_positive = float(sample.get("score", 0.0) or 0.0) >= float(threshold)
        if label == POSITIVE_LABEL and pred_positive:
            tp += 1
        elif label == NEGATIVE_LABEL and pred_positive:
            fp += 1
        elif label == POSITIVE_LABEL and not pred_positive:
            fn += 1
        else:
            tn += 1
    return compute_metrics(tp, fp, fn, tn)


def _subset_dataset(dataset: Dict[str, Any], run_ids: set[str]) -> Dict[str, Any]:
    subset = {
        "runs": [run for run in dataset.get("runs", []) if run.get("run_id") in run_ids],
        "process_samples": [item for item in dataset.get("process_samples", []) if item.get("run_id") in run_ids],
        "window_samples": [item for item in dataset.get("window_samples", []) if item.get("run_id") in run_ids],
        "role_samples": [item for item in dataset.get("role_samples", []) if item.get("run_id") in run_ids],
        "scenario_samples": [item for item in dataset.get("scenario_samples", []) if item.get("run_id") in run_ids],
        "run_debug": {run_id: debug for run_id, debug in (dataset.get("run_debug") or {}).items() if run_id in run_ids},
    }
    return subset


def evaluate_dataset(dataset: Dict[str, Any], threshold: float) -> Dict[str, Any]:
    process_samples = dataset.get("process_samples", []) or []
    window_samples = dataset.get("window_samples", []) or []
    role_samples = dataset.get("role_samples", []) or []
    scenario_samples = dataset.get("scenario_samples", []) or []

    summary: Dict[str, Any] = {
        "threshold": float(threshold),
        "run_count": len(dataset.get("runs", []) or []),
        "scenario_ids": sorted({str(item.get("scenario_id") or "") for item in process_samples + window_samples + role_samples + scenario_samples if item.get("scenario_id")}),
        "process_level": _summarize_samples(process_samples, threshold),
        "window_level": _summarize_samples(window_samples, threshold),
        "role_level": _summarize_samples(role_samples, threshold),
        "scenario_level": _summarize_samples(scenario_samples, threshold),
        "by_scenario": {},
        "by_role": {},
    }

    for scenario_id in sorted({item.get("scenario_id") for item in process_samples + window_samples + role_samples + scenario_samples if item.get("scenario_id")}):
        summary["by_scenario"][scenario_id] = {
            "process_level": _summarize_samples([item for item in process_samples if item.get("scenario_id") == scenario_id], threshold),
            "window_level": _summarize_samples([item for item in window_samples if item.get("scenario_id") == scenario_id], threshold),
            "role_level": _summarize_samples([item for item in role_samples if item.get("scenario_id") == scenario_id], threshold),
            "scenario_level": _summarize_samples([item for item in scenario_samples if item.get("scenario_id") == scenario_id], threshold),
        }

    for role_name in ALLOWED_ROLES:
        process_subset = [item for item in process_samples if item.get("role") == role_name]
        role_subset = [item for item in role_samples if item.get("role") == role_name]
        if not process_subset and not role_subset:
            continue
        summary["by_role"][role_name] = {
            "process_level": _summarize_samples(process_subset, threshold),
            "role_level": _summarize_samples(role_subset, threshold),
        }

    return summary


def evaluate_single_run(
    windows_dir: str | Path,
    labels_path: str | Path | None = None,
    run_meta_path: str | Path | None = None,
    threshold: float = DEFAULT_THRESHOLD,
    limit: int = 0,
    engine: Optional[AnalysisEngine] = None,
    include_debug: bool = False,
) -> Dict[str, Any]:
    windows_path = Path(windows_dir)
    run_dir = windows_path.parent
    run_meta = load_run_meta(run_meta_path)
    scenario_id = str(run_meta.get("scenario_id") or run_dir.parent.name or "adhoc").strip()
    kind = str(run_meta.get("kind") or "unknown").strip().lower() or "unknown"
    repeat_id = _infer_repeat_id(run_dir, run_meta)
    run = RunArtifacts(
        run_id=run_dir.name,
        run_dir=run_dir,
        windows_dir=windows_path,
        scenario_id=scenario_id,
        repeat_id=repeat_id,
        kind=kind,
        labels_path=Path(labels_path) if labels_path else None,
        run_meta_path=Path(run_meta_path) if run_meta_path else None,
    )
    dataset = build_dataset([run], engine=engine, limit=limit, include_debug=include_debug)
    result = evaluate_dataset(dataset, threshold)
    if include_debug:
        result["debug"] = dataset.get("run_debug", {}).get(run.run_id, {})
    return result


def _pick_best_threshold(sweep: Sequence[Dict[str, Any]]) -> float:
    if not sweep:
        return DEFAULT_THRESHOLD
    ranked = sorted(
        sweep,
        key=lambda item: (
            float(((item.get("summary") or {}).get("window_level") or {}).get("f1", 0.0)),
            float(((item.get("summary") or {}).get("window_level") or {}).get("precision", 0.0)),
            float(((item.get("summary") or {}).get("scenario_level") or {}).get("recall", 0.0)),
            -abs(float(item.get("threshold", DEFAULT_THRESHOLD)) - DEFAULT_THRESHOLD),
        ),
        reverse=True,
    )
    return float(ranked[0].get("threshold", DEFAULT_THRESHOLD))


def evaluate_benchmark_root(
    benchmark_root: str | Path,
    threshold: float = DEFAULT_THRESHOLD,
    threshold_sweep: bool = False,
    engine: Optional[AnalysisEngine] = None,
    run_id_filter: Optional[set[str]] = None,
) -> Dict[str, Any]:
    runs = collect_benchmark_runs(benchmark_root)
    if run_id_filter:
        runs = [run for run in runs if run.run_id in set(run_id_filter)]
    if not runs:
        raise ValueError(f"no benchmark runs found under {benchmark_root}")

    dataset = build_dataset(runs, engine=engine, include_debug=False)
    fixed_all = evaluate_dataset(dataset, threshold)
    if not threshold_sweep:
        return fixed_all

    validation_run_ids = {run.run_id for run in runs if int(run.repeat_id) == 1}
    if not validation_run_ids:
        validation_run_ids = {run.run_id for run in runs}
    test_run_ids = {run.run_id for run in runs if run.run_id not in validation_run_ids}
    validation_dataset = _subset_dataset(dataset, validation_run_ids)
    test_dataset = _subset_dataset(dataset, test_run_ids or validation_run_ids)

    sweep_results = []
    for candidate in DEFAULT_SWEEP_THRESHOLDS:
        sweep_results.append(
            {
                "threshold": float(candidate),
                "summary": evaluate_dataset(validation_dataset, float(candidate)),
            }
        )

    tuned_threshold = _pick_best_threshold(sweep_results)
    return {
        "split": {
            "validation_run_ids": sorted(validation_run_ids),
            "test_run_ids": sorted(test_run_ids),
            "test_fallback_to_validation": not bool(test_run_ids),
        },
        "threshold_sweep": sweep_results,
        "fixed_threshold": {
            "threshold": float(threshold),
            "validation": evaluate_dataset(validation_dataset, float(threshold)),
            "test": evaluate_dataset(test_dataset, float(threshold)),
            "all": fixed_all,
        },
        "tuned_threshold": {
            "threshold": tuned_threshold,
            "validation": evaluate_dataset(validation_dataset, tuned_threshold),
            "test": evaluate_dataset(test_dataset, tuned_threshold),
            "all": evaluate_dataset(dataset, tuned_threshold),
        },
    }


def _print_level(title: str, payload: Dict[str, Any]) -> None:
    print(title, json.dumps(payload, ensure_ascii=False))


def print_summary(summary: Dict[str, Any]) -> None:
    if "fixed_threshold" in summary and "tuned_threshold" in summary:
        fixed_test = (summary.get("fixed_threshold") or {}).get("test") or {}
        tuned_test = (summary.get("tuned_threshold") or {}).get("test") or {}
        print("fixed_threshold", float((summary.get("fixed_threshold") or {}).get("threshold", DEFAULT_THRESHOLD)))
        _print_level("fixed_window_level", fixed_test.get("window_level") or {})
        _print_level("fixed_scenario_level", fixed_test.get("scenario_level") or {})
        _print_level("fixed_role_level", fixed_test.get("role_level") or {})
        _print_level("fixed_process_level", fixed_test.get("process_level") or {})
        print("")
        print("tuned_threshold", float((summary.get("tuned_threshold") or {}).get("threshold", DEFAULT_THRESHOLD)))
        _print_level("tuned_window_level", tuned_test.get("window_level") or {})
        _print_level("tuned_scenario_level", tuned_test.get("scenario_level") or {})
        _print_level("tuned_role_level", tuned_test.get("role_level") or {})
        _print_level("tuned_process_level", tuned_test.get("process_level") or {})
        return

    print("threshold", float(summary.get("threshold", DEFAULT_THRESHOLD)))
    _print_level("window_level", summary.get("window_level") or {})
    _print_level("scenario_level", summary.get("scenario_level") or {})
    _print_level("role_level", summary.get("role_level") or {})
    _print_level("process_level", summary.get("process_level") or {})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--windows-dir", default="data/processed/realtime_windows")
    ap.add_argument("--run-meta", default="data/processed/realtime_debug/run_meta.json")
    ap.add_argument("--labels-path", default="")
    ap.add_argument("--benchmark-root", default="")
    ap.add_argument("--threshold", type=float, default=None)
    ap.add_argument("--threshold-sweep", action="store_true", default=False)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--output-json", default="")
    args = ap.parse_args()

    threshold = float(args.threshold) if args.threshold is not None else DEFAULT_THRESHOLD
    if args.benchmark_root:
        summary = evaluate_benchmark_root(
            args.benchmark_root,
            threshold=threshold,
            threshold_sweep=bool(args.threshold_sweep),
        )
    else:
        run_meta = load_run_meta(args.run_meta)
        if args.threshold is None:
            threshold = float(run_meta.get("threshold") or DEFAULT_THRESHOLD)
        summary = evaluate_single_run(
            args.windows_dir,
            labels_path=(args.labels_path or None),
            run_meta_path=(args.run_meta or None),
            threshold=threshold,
            limit=int(args.limit),
            include_debug=False,
        )

    print_summary(summary)
    if args.output_json:
        write_json(args.output_json, summary)


if __name__ == "__main__":
    main()
