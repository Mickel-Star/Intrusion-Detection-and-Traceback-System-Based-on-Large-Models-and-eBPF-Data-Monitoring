#!/usr/bin/env python3
from __future__ import annotations

"""Knowledge base builders.

本模块负责三个构建入口：
1. `build_tik`：构建威胁情报向量库。
2. `build_ark`：构建 MITRE 逻辑图。
3. `build_bbk`：构建/更新 BBK，并执行两阶段 GMAE 训练

其中 `build_bbk` 是训练主入口：
- 阶段 1 把 benign 日志切成窗口，更新 BBK/Word2Vec，并落盘窗口 + manifest。
- 阶段 2 基于 manifest 做离线多 epoch 训练、calibration 和 baseline 保存。
"""

import copy
import hashlib
import math
import os
import random
import shutil
import tempfile
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable, Optional

from src.common.defaults import (
    DEFAULT_BBK_MIN_CALIBRATION_WINDOWS,
    DEFAULT_BBK_MIN_SOURCE_RUNS,
    DEFAULT_BBK_MIN_TRAIN_WINDOWS,
    DEFAULT_BBK_PROFILE_IMBALANCE_RATIO,
    DEFAULT_BBK_TRAIN_WINDOW_SECONDS,
    DEFAULT_TIME_BIN_SECONDS,
    DEFAULT_WINDOW_SECONDS,
)
from src.common.io import read_json, write_json
from src.knowledge.kb_paths import KB_PATHS


GMAE_MANIFEST_FILENAME = "gmae_windows_manifest.json"
GMAE_STAGING_PREFIX = "gmae_bbk_staging_"
GMAE_BASELINE_VERSION = 5


@dataclass
class RunningStats:
    """用在线方式累计均值/方差，避免保存无限增长的原始 loss 列表。"""

    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    min: float | None = None
    max: float | None = None

    def update(self, value: float) -> None:
        x = float(value)
        self.count += 1
        delta = x - self.mean
        self.mean += delta / float(self.count)
        delta2 = x - self.mean
        self.m2 += delta * delta2
        self.min = x if self.min is None else min(self.min, x)
        self.max = x if self.max is None else max(self.max, x)

    def to_dict(self) -> dict[str, Any]:
        if self.count <= 0:
            return {"count": 0, "mean": None, "std": None, "min": None, "max": None}
        return {
            "count": int(self.count),
            "mean": float(self.mean),
            "std": float(math.sqrt(self.m2 / float(self.count))),
            "min": float(self.min) if self.min is not None else None,
            "max": float(self.max) if self.max is not None else None,
        }


def build_tik() -> None:
    KB_PATHS.ensure_layout()

    from src.knowledge.threat_intel_kb_builder import ThreatIntelligenceKnowledgeBuilder

    builder = ThreatIntelligenceKnowledgeBuilder(db_path=KB_PATHS.tik_db_dir)
    builder.build()


def build_bbk(
    log_file: str = "",
    *,
    logs_dir: str = "",
    persist_windows_dir: str = "",
    window_seconds: int = DEFAULT_BBK_TRAIN_WINDOW_SECONDS,
    time_bin_seconds: int = DEFAULT_TIME_BIN_SECONDS,
) -> None:
    """构建 BBK，并以 manifest 为桥梁执行两阶段 GMAE 训练。"""

    KB_PATHS.ensure_layout()

    from src.knowledge.benign_behavior_kb import BenignBehaviorKnowledgeBase
    from src.process.log_parser import TraceeLogParser
    from src.process.streaming_reduction import iter_reduced_edges
    from src.process.window_io import dump_window_graph

    sources, source_mode = _resolve_bbk_sources(log_file=log_file, logs_dir=logs_dir)
    parser = TraceeLogParser()

    windows_dir, persist_windows, windows_dir_preexisting = _prepare_gmae_windows_dir(persist_windows_dir)
    manifest_path = os.path.join(windows_dir, GMAE_MANIFEST_FILENAME)
    manifest_records: list[dict[str, Any]] = []
    total_nodes = 0
    total_edges = 0
    window_idx = 0

    store = BenignBehaviorKnowledgeBase(
        db_path=KB_PATHS.bbk_db_path,
        model_path=KB_PATHS.bbk_word2vec_path,
    )

    try:
        print(f"📦 Stage 1/2: streaming benign windows into {windows_dir}")
        for source in sources:
            logs = parser.parse_log_file(str(source["log_file"]))
            source_context = _hydrate_source_runtime_context(source, logs)
            fit_for_bbk = _source_participates_in_bbk_fit(source_context, source_mode=source_mode)
            source_window_idx = 0
            for g, metas in _iter_bbk_windows(
                logs,
                window_seconds=int(window_seconds),
                time_bin_seconds=int(time_bin_seconds),
            ):
                source_window_idx += 1
                window_idx += 1
                window_id = f"window_{window_idx:04d}"
                window_path = os.path.join(windows_dir, f"{window_id}.json")

                dump_window_graph(window_path, g)
                window_start_ns, window_end_ns = _graph_time_range_ns(g)
                resolved_profile = _resolve_window_profile(
                    source_context,
                    window_start_ns=window_start_ns,
                    window_end_ns=window_end_ns,
                    window_sequence=source_window_idx,
                    window_seconds=int(window_seconds),
                )
                record = _build_manifest_record(
                    window_id,
                    window_path,
                    g,
                    source_log_file=str(source["log_file"]),
                    source_run_id=str(source.get("run_id") or ""),
                    source_profile=str(resolved_profile.get("profile_id") or ""),
                    source_phase_id=str(resolved_profile.get("phase_id") or ""),
                    split_role=str(source.get("split_role") or ""),
                    window_start_ns=window_start_ns,
                    window_end_ns=window_end_ns,
                    window_sequence=source_window_idx,
                )
                manifest_records.append(record)

                if fit_for_bbk:
                    store.update_from_edges(iter_reduced_edges(g), metas)
                    store.update_word2vec_from_metas(metas)

                total_nodes += int(record["node_count"])
                total_edges += int(record["edge_count"])
    finally:
        store.close()

    manifest_payload = _write_gmae_manifest(
        manifest_path=manifest_path,
        log_file=log_file,
        logs_dir=logs_dir,
        source_mode=source_mode,
        sources=sources,
        windows_dir=windows_dir,
        persist_windows=persist_windows,
        window_seconds=int(window_seconds),
        reduction_config=_bbk_reduction_config_payload(
            window_seconds=int(window_seconds),
            time_bin_seconds=int(time_bin_seconds),
        ),
        records=manifest_records,
    )

    print(
        f"🧠 Stage 2/2: offline GMAE training on {len(manifest_records)} windows "
        f"(manifest={manifest_path})"
    )
    runtime = _init_gmae_runtime()
    training_result = _train_gmae_from_manifest(runtime, manifest_path)

    staging_cleaned = False
    if not persist_windows and not bool(training_result.get("rejected_reason")):
        try:
            shutil.rmtree(windows_dir)
            staging_cleaned = True
        except OSError:
            staging_cleaned = False

    _save_gmae_runtime(
        runtime=runtime,
        manifest_payload=manifest_payload,
        training_result=training_result,
        context={
            "log_file": os.path.abspath(log_file) if str(log_file or "").strip() else "",
            "logs_dir": os.path.abspath(logs_dir) if str(logs_dir or "").strip() else "",
            "source_mode": source_mode,
            "windows_dir": windows_dir,
            "persist_windows": bool(persist_windows),
            "windows_dir_preexisting": bool(windows_dir_preexisting),
            "staging_cleaned": bool(staging_cleaned),
            "window_nodes_sum": int(total_nodes),
            "window_edges_sum": int(total_edges),
        },
    )

    if training_result.get("rejected_reason"):
        raise RuntimeError(str(training_result["rejected_reason"]))

    print(
        f"\n✅ BBK 基线库更新完成：window_count={len(manifest_records)}, "
        f"window_nodes_sum={total_nodes}, window_edges_sum={total_edges}"
    )


def build_ark() -> None:
    KB_PATHS.ensure_layout()

    import networkx as nx

    from src.knowledge.logic_graph_builder import LogicGraphBuilder
    from src.knowledge.stix_loader import MitreStixLoader

    techniques = MitreStixLoader().load_data()
    if not techniques:
        raise RuntimeError("无法加载 STIX 数据")

    graph = LogicGraphBuilder().build_graph(techniques)
    payload = nx.node_link_data(graph, edges="links")
    write_json(KB_PATHS.ark_graph_path, payload)
    print(f"✅ ARK 逻辑图已保存: {KB_PATHS.ark_graph_path}")


def _resolve_bbk_sources(log_file: str, logs_dir: str) -> tuple[list[dict[str, Any]], str]:
    log_file_value = str(log_file or "").strip()
    logs_dir_value = str(logs_dir or "").strip()
    if bool(log_file_value) == bool(logs_dir_value):
        raise ValueError("build_bbk requires exactly one of log_file or --logs-dir")

    if logs_dir_value:
        return _resolve_bbk_logs_dir_sources(logs_dir_value), "logs_dir"

    source = _build_single_log_source(log_file_value)
    return [source], "single_log"


def _build_single_log_source(log_file: str) -> dict[str, Any]:
    path = Path(log_file).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"benign log file not found: {path}")

    return {
        "log_file": str(path),
        "run_id": path.stem or "single_log",
        "split_role": "train",
        "source_profile": "",
        "phases": [],
        "training_pool": False,
        "bootstrap_only": True,
    }


def _resolve_bbk_logs_dir_sources(logs_dir: str) -> list[dict[str, Any]]:
    root = Path(logs_dir).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"benign corpus directory not found: {root}")

    raw_sources: list[dict[str, Any]] = []
    for run_dir in sorted([path for path in root.iterdir() if path.is_dir()], key=lambda item: item.name):
        trace_path = _discover_trace_log(run_dir)
        if trace_path is None:
            continue

        run_meta_path = run_dir / "run_meta.json"
        run_meta = read_json(str(run_meta_path)) if run_meta_path.exists() else {}
        if not isinstance(run_meta, dict):
            run_meta = {}

        training_pool = bool(run_meta.get("training_pool", True))
        if not training_pool:
            continue

        run_id = str(run_meta.get("run_id") or run_dir.name).strip() or run_dir.name
        raw_sources.append(
            {
                "log_file": str(trace_path.resolve()),
                "run_id": run_id,
                "split_role": _normalize_split_role(run_meta.get("split_role") or ""),
                "source_profile": str(run_meta.get("source_profile") or run_meta.get("primary_profile") or "").strip(),
                "phases": _normalize_source_phases(run_meta.get("phases") or []),
                "training_pool": True,
                "bootstrap_only": bool(run_meta.get("bootstrap_only", False)),
            }
        )

    if not raw_sources:
        raise ValueError(f"no benign corpus runs discovered under {root}")

    sources: list[dict[str, Any]] = []
    total = len(raw_sources)
    for idx, source in enumerate(raw_sources):
        enriched = dict(source)
        if not enriched.get("split_role"):
            enriched["split_role"] = _default_split_role_for_run(
                run_id=str(enriched.get("run_id") or ""),
                order_index=idx,
                total_runs=total,
            )
        sources.append(enriched)
    return sources


def _discover_trace_log(run_dir: Path) -> Path | None:
    preferred = run_dir / "trace.log"
    if preferred.exists() and preferred.is_file():
        return preferred

    log_candidates = sorted(
        [
            path
            for path in run_dir.iterdir()
            if path.is_file() and path.suffix.lower() in {".log", ".json", ".jsonl"}
        ],
        key=lambda item: item.name,
    )
    if len(log_candidates) == 1:
        return log_candidates[0]
    if not log_candidates:
        return None
    raise ValueError(f"multiple trace log candidates found under {run_dir}: {[item.name for item in log_candidates]}")


def _normalize_source_phases(raw_phases: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    phases: list[dict[str, Any]] = []
    cursor = 0.0
    for idx, raw in enumerate(raw_phases or []):
        if not isinstance(raw, dict):
            continue
        duration_seconds = float(raw.get("duration_seconds") or raw.get("seconds") or 0.0)
        if duration_seconds <= 0:
            continue

        start_offset = raw.get("start_offset_seconds")
        end_offset = raw.get("end_offset_seconds")
        if start_offset is None:
            start_offset = cursor
        start_value = max(float(start_offset), 0.0)
        end_value = float(end_offset) if end_offset is not None else start_value + duration_seconds
        if end_value <= start_value:
            end_value = start_value + duration_seconds

        profile_id = str(raw.get("profile_id") or raw.get("source_profile") or "").strip()
        phase_id = str(raw.get("phase_id") or f"phase_{idx + 1:02d}").strip() or f"phase_{idx + 1:02d}"
        phases.append(
            {
                "phase_id": phase_id,
                "profile_id": profile_id,
                "start_offset_seconds": float(start_value),
                "end_offset_seconds": float(end_value),
                "duration_seconds": float(end_value - start_value),
            }
        )
        cursor = end_value
    return phases


def _default_split_role_for_run(run_id: str, order_index: int, total_runs: int) -> str:
    normalized = str(run_id or "").strip().lower()
    fixed = {
        "run_a": "train",
        "run_b": "train",
        "run_c": "calibration",
        "run_d": "holdout",
    }
    if normalized in fixed:
        return fixed[normalized]

    if total_runs <= 1:
        return "train"
    if total_runs == 2:
        return "train" if order_index == 0 else "calibration"
    if total_runs == 3:
        return "calibration" if order_index == 2 else "train"
    if order_index < total_runs - 2:
        return "train"
    if order_index == total_runs - 2:
        return "calibration"
    return "holdout"


def _normalize_split_role(value: Any) -> str:
    role = str(value or "").strip().lower()
    if not role:
        return ""
    if role not in {"train", "calibration", "holdout"}:
        raise ValueError(f"unsupported benign corpus split_role: {role}")
    return role


def _hydrate_source_runtime_context(source: dict[str, Any], logs: list[dict[str, Any]]) -> dict[str, Any]:
    hydrated = dict(source)
    start_ns = _first_log_timestamp_ns(logs)
    if start_ns is not None:
        hydrated["log_start_ns"] = int(start_ns)
    return hydrated


def _first_log_timestamp_ns(logs: Iterable[dict[str, Any]]) -> int | None:
    for log in logs or []:
        raw = log.get("timestamp")
        try:
            return int(float(raw) * 1_000_000_000)
        except Exception:
            continue
    return None


def _source_participates_in_bbk_fit(source: dict[str, Any], source_mode: str) -> bool:
    if str(source_mode or "") != "logs_dir":
        return True
    return _normalize_split_role(source.get("split_role") or "") != "holdout"


def _graph_time_range_ns(g) -> tuple[int, int]:
    start_ns = None
    end_ns = None
    for _src, _dst, _key, data in g.edges(keys=True, data=True):
        first_ts = data.get("first_ts")
        last_ts = data.get("last_ts")
        try:
            first_value = int(first_ts)
            start_ns = first_value if start_ns is None else min(start_ns, first_value)
        except Exception:
            pass
        try:
            last_value = int(last_ts)
            end_ns = last_value if end_ns is None else max(end_ns, last_value)
        except Exception:
            pass
    if start_ns is None or end_ns is None:
        return 0, 0
    return int(start_ns), int(end_ns)


def _resolve_window_profile(
    source: dict[str, Any],
    *,
    window_start_ns: int,
    window_end_ns: int,
    window_sequence: int,
    window_seconds: int,
) -> dict[str, Any]:
    phases = list(source.get("phases") or [])
    static_profile = str(source.get("source_profile") or "").strip()
    if not phases:
        return {"profile_id": static_profile, "phase_id": ""}

    midpoint_offset_seconds = None
    log_start_ns = source.get("log_start_ns")
    if log_start_ns is not None and (window_start_ns > 0 or window_end_ns > 0):
        midpoint_ns = float(int(window_start_ns or 0) + int(window_end_ns or window_start_ns or 0)) / 2.0
        midpoint_offset_seconds = max((midpoint_ns - float(log_start_ns)) / 1_000_000_000.0, 0.0)

    if midpoint_offset_seconds is not None:
        resolved = _phase_for_offset_seconds(phases, midpoint_offset_seconds)
        if resolved:
            return resolved

    fallback_offset_seconds = max((float(window_sequence) - 0.5) * float(window_seconds), 0.0)
    resolved = _phase_for_offset_seconds(phases, fallback_offset_seconds)
    if resolved:
        return resolved

    tail = phases[-1]
    return {
        "profile_id": str(tail.get("profile_id") or static_profile),
        "phase_id": str(tail.get("phase_id") or ""),
    }


def _phase_for_offset_seconds(phases: list[dict[str, Any]], offset_seconds: float) -> dict[str, Any] | None:
    for phase in phases:
        start_offset = float(phase.get("start_offset_seconds") or 0.0)
        end_offset = float(phase.get("end_offset_seconds") or start_offset)
        if start_offset <= float(offset_seconds) < end_offset:
            return {
                "profile_id": str(phase.get("profile_id") or ""),
                "phase_id": str(phase.get("phase_id") or ""),
            }
    if phases and float(offset_seconds) >= float(phases[-1].get("start_offset_seconds") or 0.0):
        last = phases[-1]
        return {
            "profile_id": str(last.get("profile_id") or ""),
            "phase_id": str(last.get("phase_id") or ""),
        }
    return None


def _init_gmae_runtime() -> dict[str, Any]:
    """初始化一次 build_bbk 运行期共享的 GMAE 上下文。"""

    seed = _env_int("DRSEC_GMAE_SEED", 1337)
    epochs = max(1, _env_int("DRSEC_GMAE_EPOCHS", 10))
    calibration_ratio = min(max(_env_float("DRSEC_GMAE_CALIBRATION_RATIO", 0.2), 0.0), 1.0)
    debug_history_limit = max(1, _env_int("DRSEC_GMAE_DEBUG_HISTORY_LIMIT", 128))
    config: dict[str, Any] = {}
    device = "cpu"

    try:
        import torch

        from src.common.gmae import build_model
        from src.process.dgl_adapter import DEFAULT_EDGE_ATTR_DIM, DEFAULT_NODE_ATTR_DIM

        config = {
            "n_dim": int(os.environ.get("DRSEC_GMAE_NODE_DIM", DEFAULT_NODE_ATTR_DIM)),
            "e_dim": int(os.environ.get("DRSEC_GMAE_EDGE_DIM", DEFAULT_EDGE_ATTR_DIM)),
            "num_hidden": int(os.environ.get("DRSEC_GMAE_HIDDEN_DIM", 64)),
            "num_layers": int(os.environ.get("DRSEC_GMAE_LAYERS", 2)),
            "n_heads": int(os.environ.get("DRSEC_GMAE_HEADS", 4)),
            "mask_rate": float(os.environ.get("DRSEC_GMAE_MASK_RATE", 0.5)),
            "negative_slope": float(os.environ.get("DRSEC_GMAE_NEGATIVE_SLOPE", 0.2)),
            "alpha_l": float(os.environ.get("DRSEC_GMAE_ALPHA", 2.0)),
            "feat_drop": float(os.environ.get("DRSEC_GMAE_FEAT_DROP", 0.1)),
            "activation": os.environ.get("DRSEC_GMAE_ACTIVATION", "prelu"),
            "residual": True,
            "norm": os.environ.get("DRSEC_GMAE_NORM", "BatchNorm"),
        }

        _seed_torch(torch, seed)
        # 这里统一探测 device，避免后续每个窗口都重复做环境判断。
        device = _resolve_gmae_device(torch)
        model = build_model(SimpleNamespace(**config)).to(device)
        optimizer = torch.optim.Adam(
            model.parameters(),
            lr=float(os.environ.get("DRSEC_GMAE_LR", 1e-3)),
            weight_decay=float(os.environ.get("DRSEC_GMAE_WEIGHT_DECAY", 1e-5)),
        )

        return {
            "torch": torch,
            "config": config,
            "device": device,
            "model": model,
            "optimizer": optimizer,
            "seed": int(seed),
            "epochs": int(epochs),
            "calibration_ratio": float(calibration_ratio),
            "debug_history_limit": int(debug_history_limit),
            "disabled_reason": None,
        }
    except Exception as exc:
        print(f"Warning: GMAE runtime unavailable, skipping GNN baseline training: {exc}")
        return {
            "config": config,
            "device": device,
            "seed": int(seed),
            "epochs": int(epochs),
            "calibration_ratio": float(calibration_ratio),
            "debug_history_limit": int(debug_history_limit),
            "disabled_reason": str(exc),
        }


def _iter_bbk_windows(
    logs: Iterable[dict[str, Any]],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    time_bin_seconds: int = DEFAULT_TIME_BIN_SECONDS,
):
    """按 streaming reduction 逻辑把日志切成训练窗口。"""

    from src.process.provenance_model import ProvenanceEventMapper
    from src.process.streaming_reduction import StreamingReducer, StreamingReductionConfig

    reducer = StreamingReducer(
        mapper=ProvenanceEventMapper(),
        config=StreamingReductionConfig(
            window_seconds=int(window_seconds),
            time_bin_seconds=int(time_bin_seconds),
        ),
    )
    yield from reducer.ingest_logs(logs)


def _bbk_reduction_config_payload(window_seconds: int, time_bin_seconds: int = DEFAULT_TIME_BIN_SECONDS) -> dict[str, Any]:
    from src.process.streaming_reduction import StreamingReductionConfig

    return StreamingReductionConfig(
        window_seconds=int(window_seconds),
        time_bin_seconds=int(time_bin_seconds),
    ).to_dict()


def _resolve_gmae_device(torch_module) -> str:
    if not torch_module.cuda.is_available():
        return "cpu"
    try:
        import dgl

        graph = dgl.graph(
            (
                torch_module.tensor([], dtype=torch_module.int64),
                torch_module.tensor([], dtype=torch_module.int64),
            ),
            num_nodes=0,
        )
        graph = graph.to("cuda")
        del graph
        return "cuda"
    except Exception:
        return "cpu"


def _train_gmae_from_manifest(runtime: dict[str, Any], manifest_path: str) -> dict[str, Any]:
    """基于 manifest 执行完整的多 epoch 训练与 checkpoint 选择。"""
    manifest_payload = read_json(manifest_path)  # 读取训练数据manifest清单
    records = list(manifest_payload.get("records") or [])
    manifest_summary = dict(manifest_payload.get("summary") or _summarize_manifest_records(records))

    seed = int(runtime.get("seed") or 0)
    calibration_ratio = float(runtime.get("calibration_ratio") or 0.0)
    epochs = int(runtime.get("epochs") or 0)
    debug_history = deque(maxlen=int(runtime.get("debug_history_limit") or 128))
    # 划分训练集和验证集
    split = _split_gmae_manifest(
        records,
        seed=seed,
        calibration_ratio=calibration_ratio,
        source_mode=str(manifest_payload.get("source_mode") or ""),
    )
    split_summary = dict(split["summary"])
    quality = _evaluate_training_quality(manifest_payload, split_summary)
    has_calibration_split = int(split_summary.get("calibration_window_count") or 0) > 0
    # 确定最优模型的评价指标：有校准集 → 用重构误差；无 → 用训练损失
    preferred_metric = (
        "calibration_mean_process_reconstruction_error"
        if has_calibration_split
        else "train_mean_total_loss"
    )

    training_counters = {
        "trained_updates": 0,
        "skipped_empty_windows": 0,
        "skipped_nonfinite_windows": 0,
        "failed_windows": 0,
    }
    aggregate_losses = _new_loss_trackers()
    epoch_metric_summary: list[dict[str, Any]] = []
    best_state_dict: dict[str, Any] | None = None
    best_epoch = None
    best_metric_value = None
    best_calibration = None
    best_calibration_summary = None
    fallback_train_best_state_dict: dict[str, Any] | None = None
    fallback_train_best_epoch = None
    fallback_train_best_metric_value = None
    selected_checkpoint_metric = preferred_metric
    epochs_completed = 0

    if quality["errors"]:
        return {
            "saved_baseline": False,
            "disabled_reason": runtime.get("disabled_reason"),
            "manifest_summary": manifest_summary,
            "split_summary": split_summary,
            "training_summary": {
                **training_counters,
                "total_loss": aggregate_losses["total_loss"].to_dict(),
                "node_recon_loss": aggregate_losses["node_recon_loss"].to_dict(),
                "structure_loss": aggregate_losses["structure_loss"].to_dict(),
            },
            "epoch_metric_summary": epoch_metric_summary,
            "debug_history": list(debug_history),
            "selected_checkpoint_metric": preferred_metric,
            "best_epoch": None,
            "best_metric_value": None,
            "final_epoch": epochs,
            "epochs_completed": 0,
            "process_error_calibration": None,
            "best_calibration_summary": None,
            "quality_gate_errors": list(quality["errors"]),
            "rejected_reason": "; ".join(str(item) for item in quality["errors"]),
            "imbalance_warning": quality["imbalance_warning"],
            "training_tier": quality["training_tier"],
            "profile_window_distribution": dict(split_summary.get("profile_window_distribution") or {}),
            "source_run_ids": list(split_summary.get("source_run_ids") or []),
            "holdout_run_ids": list(split_summary.get("holdout_run_ids") or []),
        }

    if runtime.get("disabled_reason"):
        return {
            "saved_baseline": False,
            "disabled_reason": runtime.get("disabled_reason"),
            "manifest_summary": manifest_summary,
            "split_summary": split_summary,
            "training_summary": {
                **training_counters,
                "total_loss": aggregate_losses["total_loss"].to_dict(),
                "node_recon_loss": aggregate_losses["node_recon_loss"].to_dict(),
                "structure_loss": aggregate_losses["structure_loss"].to_dict(),
            },
            "epoch_metric_summary": epoch_metric_summary,
            "debug_history": list(debug_history),
            "selected_checkpoint_metric": preferred_metric,
            "best_epoch": None,
            "best_metric_value": None,
            "final_epoch": epochs,
            "epochs_completed": 0,
            "process_error_calibration": None,
            "best_calibration_summary": None,
            "quality_gate_errors": [],
            "rejected_reason": None,
            "imbalance_warning": quality["imbalance_warning"],
            "training_tier": quality["training_tier"],
            "profile_window_distribution": dict(split_summary.get("profile_window_distribution") or {}),
            "source_run_ids": list(split_summary.get("source_run_ids") or []),
            "holdout_run_ids": list(split_summary.get("holdout_run_ids") or []),
        }

    for epoch in range(1, epochs + 1):
        # 每轮初始化：当前轮计数器、损失
        epochs_completed = epoch
        epoch_counters = {
            "trained_updates": 0,
            "skipped_empty_windows": 0,
            "skipped_nonfinite_windows": 0,
            "failed_windows": 0,
        }
        epoch_losses = _new_loss_trackers()

        # 同一窗口在一个 epoch 内只训练一次，但跨 epoch 会重复参与
        for record in _epoch_train_order(split["train_records"], seed, epoch):
            # 真正训练：单张图窗口 → 前向传播 → 算损失 → 反向更新模型
            outcome = _train_gmae_on_window(runtime, record, epoch)
            _append_debug_history(
                debug_history,
                epoch=epoch,
                window_id=str(record.get("window_id") or ""),
                skipped=bool(outcome["skipped"]),
                reason=str(outcome.get("reason") or ""),
                losses=outcome.get("losses"),
            )
            # 如果训练被跳过（空图/无效图/损失异常）：统计跳过次数
            if outcome["skipped"]:
                _increment_skip_counters(training_counters, epoch_counters, str(outcome.get("skip_kind") or "failed"))
                continue

            losses = dict(outcome["losses"])
            training_counters["trained_updates"] += 1
            epoch_counters["trained_updates"] += 1
            # 训练成功：累计损失 + 计数
            _update_loss_trackers(aggregate_losses, losses)
            _update_loss_trackers(epoch_losses, losses)

        for record in split["empty_records"]:
            _append_debug_history(
                debug_history,
                epoch=epoch,
                window_id=str(record.get("window_id") or ""),
                skipped=True,
                reason="empty_graph",
                losses=None,
            )
            _increment_skip_counters(training_counters, epoch_counters, "empty")

        # 每个 epoch 结束后都在 calibration split 上重算进程节点误差，
        # 这样 checkpoint 选择依赖的是 epoch 级验证指标，而不是最终一次性统计。
        calibration_result = _evaluate_gmae_calibration(runtime, split["calibration_records"])
        checkpoint_metric_name = None
        checkpoint_metric_value = None
        calibration_summary = calibration_result["summary"] if calibration_result else _empty_distribution_summary()
        train_metric_value = float(epoch_losses["total_loss"].mean) if epoch_losses["total_loss"].count > 0 else None

        # 即使主路径优先使用 calibration，也维护一份 train-loss 最优 checkpoint，
        # 以便 calibration split 存在但本轮没有拿到有效分数时还能安全回退。
        if train_metric_value is not None and math.isfinite(train_metric_value):
            if fallback_train_best_metric_value is None or train_metric_value < float(fallback_train_best_metric_value):
                fallback_train_best_metric_value = float(train_metric_value)
                fallback_train_best_epoch = int(epoch)
                fallback_train_best_state_dict = _clone_state_dict_to_cpu(runtime["model"].state_dict())

        # 规则固定为：
        # - 有 calibration split：只用 calibration mean 选主 checkpoint。
        # - 无 calibration split：退化为 train total loss。
        if has_calibration_split:
            if calibration_result and calibration_result.get("payload") and calibration_summary.get("mean") is not None:
                checkpoint_metric_name = "calibration_mean_process_reconstruction_error"
                checkpoint_metric_value = float(calibration_summary["mean"])
        elif train_metric_value is not None:
            checkpoint_metric_name = "train_mean_total_loss"
            checkpoint_metric_value = float(train_metric_value)

        is_best_checkpoint = False
        if checkpoint_metric_value is not None and math.isfinite(checkpoint_metric_value):
            if best_metric_value is None or checkpoint_metric_value < float(best_metric_value):
                best_metric_value = float(checkpoint_metric_value)
                best_epoch = int(epoch)
                best_state_dict = _clone_state_dict_to_cpu(runtime["model"].state_dict())
                best_calibration = calibration_result["payload"] if calibration_result else None
                best_calibration_summary = calibration_summary if calibration_result else None
                selected_checkpoint_metric = str(checkpoint_metric_name or preferred_metric)
                is_best_checkpoint = True

        epoch_metric_summary.append(
            {
                "epoch": int(epoch),
                "trained_updates": int(epoch_counters["trained_updates"]),
                "skipped_empty_windows": int(epoch_counters["skipped_empty_windows"]),
                "skipped_nonfinite_windows": int(epoch_counters["skipped_nonfinite_windows"]),
                "failed_windows": int(epoch_counters["failed_windows"]),
                "train_total_loss": epoch_losses["total_loss"].to_dict(),
                "train_node_recon_loss": epoch_losses["node_recon_loss"].to_dict(),
                "train_structure_loss": epoch_losses["structure_loss"].to_dict(),
                "calibration_process_error": calibration_summary,
                "checkpoint_metric_name": checkpoint_metric_name,
                "checkpoint_metric_value": checkpoint_metric_value,
                "is_best_checkpoint": bool(is_best_checkpoint),
            }
        )

    # 兜底逻辑：有 calibration split，但所有 epoch 都没有拿到可用 calibration 分数时，
    # 仍然允许回退到 train-loss 最优 checkpoint，而不是整次训练直接不产出 baseline。
    if (
        best_state_dict is None
        and has_calibration_split
        and training_counters["trained_updates"] > 0
        and fallback_train_best_state_dict is not None
    ):
        best_state_dict = fallback_train_best_state_dict
        best_epoch = int(fallback_train_best_epoch) if fallback_train_best_epoch is not None else None
        best_metric_value = float(fallback_train_best_metric_value) if fallback_train_best_metric_value is not None else None
        best_calibration = None
        best_calibration_summary = None
        selected_checkpoint_metric = "train_mean_total_loss"
        if best_epoch is not None and 1 <= best_epoch <= len(epoch_metric_summary):
            epoch_metric_summary[best_epoch - 1]["checkpoint_metric_name"] = "train_mean_total_loss"
            epoch_metric_summary[best_epoch - 1]["checkpoint_metric_value"] = best_metric_value
            epoch_metric_summary[best_epoch - 1]["is_best_checkpoint"] = True

    training_summary = {
        "trained_updates": int(training_counters["trained_updates"]),
        "skipped_empty_windows": int(training_counters["skipped_empty_windows"]),
        "skipped_nonfinite_windows": int(training_counters["skipped_nonfinite_windows"]),
        "failed_windows": int(training_counters["failed_windows"]),
        "total_loss": aggregate_losses["total_loss"].to_dict(),
        "node_recon_loss": aggregate_losses["node_recon_loss"].to_dict(),
        "structure_loss": aggregate_losses["structure_loss"].to_dict(),
    }

    return {
        "saved_baseline": bool(best_state_dict is not None and training_counters["trained_updates"] > 0),
        "disabled_reason": runtime.get("disabled_reason"),
        "manifest_summary": manifest_summary,
        "split_summary": split_summary,
        "training_summary": training_summary,
        "epoch_metric_summary": epoch_metric_summary,
        "debug_history": list(debug_history),
        "selected_checkpoint_metric": selected_checkpoint_metric,
        "best_epoch": best_epoch,
        "best_metric_value": best_metric_value,
        "final_epoch": epochs,
        "epochs_completed": epochs_completed,
        "state_dict": best_state_dict,
        "process_error_calibration": best_calibration,
        "best_calibration_summary": best_calibration_summary,
        "quality_gate_errors": [],
        "rejected_reason": None,
        "imbalance_warning": quality["imbalance_warning"],
        "training_tier": quality["training_tier"],
        "profile_window_distribution": dict(split_summary.get("profile_window_distribution") or {}),
        "source_run_ids": list(split_summary.get("source_run_ids") or []),
        "holdout_run_ids": list(split_summary.get("holdout_run_ids") or []),
    }


def _train_gmae_on_window(runtime: dict[str, Any], record: dict[str, Any], epoch: int) -> dict[str, Any]:
    """对单个窗口执行一次参数更新，并返回标准化的结果结构。"""

    from src.process.dgl_adapter import window_to_dgl_graph
    from src.process.window_io import load_window_graph

    # manifest 已经提前标了 trainable，这里先走一次快路径，避免无意义 I/O。
    if not bool(record.get("trainable")):
        return {"skipped": True, "skip_kind": "empty", "reason": "empty_graph", "losses": None}

    torch = runtime["torch"]
    model = runtime["model"]
    optimizer = runtime["optimizer"]

    try:
        graph = load_window_graph(str(record["path"]))
        if int(graph.number_of_nodes()) <= 0:
            return {"skipped": True, "skip_kind": "empty", "reason": "empty_graph", "losses": None}

        # 对每个 epoch/window 派生稳定 seed，保证 mask/negative sampling 可复现，
        # 同时不同 epoch 又不会完全重复。
        _seed_torch(torch, _stable_step_seed(int(runtime["seed"]), int(epoch), str(record["window_id"])))
        adapter = window_to_dgl_graph(
            graph,
            node_attr_dim=int(runtime["config"]["n_dim"]),
            edge_attr_dim=int(runtime["config"]["e_dim"]),
            device=runtime["device"],
        )
        dgl_graph = adapter.graph
        if int(dgl_graph.num_nodes()) <= 0:
            return {"skipped": True, "skip_kind": "empty", "reason": "empty_graph", "losses": None}

        model.train()
        optimizer.zero_grad(set_to_none=True)
        components = model.compute_loss_components(dgl_graph)

        # 训练时同时记录分解后的 loss，外层会把它们汇总到 epoch/全局统计里。
        total_loss = components["total_loss"]
        node_recon_loss = components["node_recon_loss"]
        structure_loss = components["structure_loss"]
        if not (
            _is_finite_tensor(torch, total_loss)
            and _is_finite_tensor(torch, node_recon_loss)
            and _is_finite_tensor(torch, structure_loss)
        ):
            optimizer.zero_grad(set_to_none=True)
            return {
                "skipped": True,
                "skip_kind": "nonfinite",
                "reason": "nonfinite_loss",
                "losses": {
                    "total_loss": _tensor_to_float(total_loss),
                    "node_recon_loss": _tensor_to_float(node_recon_loss),
                    "structure_loss": _tensor_to_float(structure_loss),
                },
            }

        total_loss.backward()
        # 简单裁剪一下梯度，降低个别坏窗口把参数一步打飞的概率。
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
        optimizer.step()
        return {
            "skipped": False,
            "skip_kind": None,
            "reason": "",
            "losses": {
                "total_loss": _tensor_to_float(total_loss),
                "node_recon_loss": _tensor_to_float(node_recon_loss),
                "structure_loss": _tensor_to_float(structure_loss),
            },
        }
    except Exception as exc:
        # 单窗口失败不应中断整轮训练；外层只累加 failed_windows 并写 debug history。
        try:
            optimizer.zero_grad(set_to_none=True)
        except Exception:
            pass
        return {
            "skipped": True,
            "skip_kind": "failed",
            "reason": _short_reason(str(exc)),
            "losses": None,
        }


def _evaluate_gmae_calibration(
    runtime: dict[str, Any],
    calibration_records: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """在 calibration split 上统计进程节点重建误差，并构造经验分布。"""

    if not calibration_records:
        return None

    from src.process.dgl_adapter import window_to_dgl_graph
    from src.process.window_io import load_window_graph

    torch = runtime["torch"]
    model = runtime["model"]
    model.eval()

    scores: list[float] = []
    valid_windows = 0
    failed_windows = 0

    with torch.no_grad():
        for record in sorted(calibration_records, key=lambda item: str(item.get("window_id") or "")):
            try:
                graph = load_window_graph(str(record["path"]))
                if int(graph.number_of_nodes()) <= 0:
                    continue

                adapter = window_to_dgl_graph(
                    graph,
                    node_attr_dim=int(runtime["config"]["n_dim"]),
                    edge_attr_dim=int(runtime["config"]["e_dim"]),
                    device=runtime["device"],
                )
                if not adapter.process_node_indices:
                    continue

                node_errors = model.compute_node_reconstruction_errors(
                    adapter.graph,
                    node_indices=adapter.process_node_indices,
                )
                window_has_scores = False
                for idx in adapter.process_node_indices:
                    value = float(node_errors[idx].detach().cpu().item())
                    if math.isfinite(value):
                        scores.append(value)
                        window_has_scores = True
                if window_has_scores:
                    valid_windows += 1
            except Exception:
                failed_windows += 1

    # payload 只保存排序后的原始误差分布；统计摘要单独放在 summary 中
    scores.sort()
    summary = _summarize_distribution(scores)
    summary["requested_window_count"] = int(len(calibration_records))
    summary["valid_window_count"] = int(valid_windows)
    summary["failed_window_count"] = int(failed_windows)

    return {
        "payload": {"type": "empirical_cdf", "scores": scores, "count": len(scores)} if scores else None,
        "summary": summary,
    }


def _save_gmae_runtime(
    runtime: dict[str, Any],
    manifest_payload: dict[str, Any],
    training_result: dict[str, Any],
    context: dict[str, Any],
) -> None:
    """保存最佳 checkpoint 的推理载荷和训练诊断 sidecar。"""

    # `.meta.json` 用于训练诊断，字段可以扩展；推理主链路不依赖它。
    meta_payload = {
        "baseline_version": GMAE_BASELINE_VERSION,
        "log_file": context["log_file"],
        "logs_dir": context["logs_dir"],
        "source_mode": context["source_mode"],
        "windows_dir": context["windows_dir"],
        "persist_windows": bool(context["persist_windows"]),
        "windows_dir_preexisting": bool(context["windows_dir_preexisting"]),
        "staging_cleaned": bool(context["staging_cleaned"]),
        "manifest_path": manifest_payload.get("manifest_path"),
        "reduction_config": dict(manifest_payload.get("reduction_config") or {}),
        "manifest_summary": training_result.get("manifest_summary") or manifest_payload.get("summary") or {},
        "split_summary": training_result.get("split_summary") or {},
        "split_strategy": (training_result.get("split_summary") or {}).get("split_strategy"),
        "seed": int(runtime.get("seed") or 0),
        "epochs_requested": int(runtime.get("epochs") or 0),
        "epochs_completed": int(training_result.get("epochs_completed") or 0),
        "selected_checkpoint_metric": training_result.get("selected_checkpoint_metric"),
        "best_epoch": training_result.get("best_epoch"),
        "best_metric_value": training_result.get("best_metric_value"),
        "final_epoch": training_result.get("final_epoch"),
        "train_window_count": int((training_result.get("split_summary") or {}).get("train_window_count") or 0),
        "calibration_window_count": int((training_result.get("split_summary") or {}).get("calibration_window_count") or 0),
        "window_nodes_sum": int(context["window_nodes_sum"]),
        "window_edges_sum": int(context["window_edges_sum"]),
        "training_summary": training_result.get("training_summary") or {},
        "best_calibration_summary": training_result.get("best_calibration_summary"),
        "training_tier": training_result.get("training_tier"),
        "quality_gate_errors": list(training_result.get("quality_gate_errors") or []),
        "rejected_reason": training_result.get("rejected_reason"),
        "imbalance_warning": training_result.get("imbalance_warning"),
        "source_run_ids": list(training_result.get("source_run_ids") or (training_result.get("split_summary") or {}).get("source_run_ids") or []),
        "training_source_run_ids": list((training_result.get("split_summary") or {}).get("training_source_run_ids") or []),
        "holdout_run_ids": list(training_result.get("holdout_run_ids") or (training_result.get("split_summary") or {}).get("holdout_run_ids") or []),
        "profile_window_distribution": dict(training_result.get("profile_window_distribution") or (training_result.get("split_summary") or {}).get("profile_window_distribution") or {}),
        "epoch_metric_summary": list(training_result.get("epoch_metric_summary") or []),
        "debug_history": list(training_result.get("debug_history") or []),
        "saved_baseline": bool(training_result.get("saved_baseline")),
        "disabled_reason": training_result.get("disabled_reason"),
    }
    write_json(KB_PATHS.gmae_baseline_meta_path, meta_payload)

    if runtime.get("disabled_reason"):
        print(f"Warning: GMAE baseline was not saved: {runtime['disabled_reason']}")
        return

    if training_result.get("rejected_reason"):
        print(f"Warning: GMAE baseline was not saved because training was rejected: {training_result['rejected_reason']}")
        return

    if not bool(training_result.get("saved_baseline")):
        print("Warning: GMAE baseline was not saved because no successful training checkpoint was produced.")
        return

    state_dict = training_result.get("state_dict")
    if not isinstance(state_dict, dict) or not state_dict:
        print("Warning: GMAE baseline was not saved because no checkpoint was selected.")
        return

    torch = runtime["torch"]
    # `.pth` 只保存推理真正需要的载荷，以及少量兼容元数据。
    payload = {
        "baseline_version": GMAE_BASELINE_VERSION,
        "state_dict": state_dict,
        "config": runtime["config"],
        "device": runtime["device"],
        "trained_windows": int((training_result.get("training_summary") or {}).get("trained_updates") or 0),
        "avg_train_loss": (training_result.get("training_summary") or {}).get("total_loss", {}).get("mean"),
        "seed": int(runtime["seed"]),
        "epochs_completed": int(training_result.get("epochs_completed") or 0),
        "selected_checkpoint_metric": training_result.get("selected_checkpoint_metric"),
        "best_epoch": training_result.get("best_epoch"),
        "final_epoch": training_result.get("final_epoch"),
        "split_strategy": (training_result.get("split_summary") or {}).get("split_strategy"),
        "reduction_config": dict(manifest_payload.get("reduction_config") or {}),
        "train_window_count": int((training_result.get("split_summary") or {}).get("train_window_count") or 0),
        "calibration_window_count": int((training_result.get("split_summary") or {}).get("calibration_window_count") or 0),
        "source_run_ids": list(training_result.get("source_run_ids") or []),
        "holdout_run_ids": list(training_result.get("holdout_run_ids") or []),
    }

    calibration = training_result.get("process_error_calibration")
    if isinstance(calibration, dict):
        payload["process_error_calibration"] = calibration

    torch.save(payload, KB_PATHS.gmae_baseline_path)
    print(f"✅ GMAE baseline saved: {KB_PATHS.gmae_baseline_path}")
    print(f"📝 GMAE training metadata saved: {KB_PATHS.gmae_baseline_meta_path}")


def _prepare_gmae_windows_dir(persist_windows_dir: str) -> tuple[str, bool, bool]:
    """确定窗口目录。

    - 用户显式传目录：复用该目录，并清理上一次生成的 window/manifest 文件。
    - 未显式传目录：在 `data/processed` 下创建临时 staging 目录，训练后清理。
    """

    requested_dir = str(persist_windows_dir or "").strip()
    if requested_dir:
        abs_dir = os.path.abspath(requested_dir)
        preexisting = os.path.isdir(abs_dir)
        os.makedirs(abs_dir, exist_ok=True)
        _cleanup_generated_window_files(abs_dir)
        return abs_dir, True, preexisting

    processed_dir = os.path.abspath(os.path.join("data", "processed"))
    os.makedirs(processed_dir, exist_ok=True)
    staging_dir = tempfile.mkdtemp(prefix=GMAE_STAGING_PREFIX, dir=processed_dir)
    return staging_dir, False, False


def _cleanup_generated_window_files(directory: str) -> None:
    try:
        entries = os.listdir(directory)
    except OSError:
        return

    generated_names = {GMAE_MANIFEST_FILENAME}
    for name in entries:
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        if name in generated_names or (name.startswith("window_") and name.endswith(".json")):
            try:
                os.remove(path)
            except OSError:
                continue


def _write_gmae_manifest(
    manifest_path: str,
    log_file: str,
    logs_dir: str,
    source_mode: str,
    sources: list[dict[str, Any]],
    windows_dir: str,
    persist_windows: bool,
    window_seconds: int,
    reduction_config: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    """把阶段 1 产出的窗口索引写成 manifest，供离线训练阶段消费"""

    payload = {
        "manifest_version": 2,
        "source_mode": str(source_mode or ""),
        "log_file": os.path.abspath(log_file) if str(log_file or "").strip() else "",
        "logs_dir": os.path.abspath(logs_dir) if str(logs_dir or "").strip() else "",
        "windows_dir": os.path.abspath(windows_dir),
        "persist_windows": bool(persist_windows),
        "window_seconds": int(window_seconds),
        "reduction_config": dict(reduction_config or {}),
        "source_count": int(len(sources)),
        "sources": [_serialize_manifest_source(source) for source in sources],
        "record_count": int(len(records)),
        "summary": _summarize_manifest_records(records),
        "records": records,
    }
    write_json(manifest_path, payload)
    payload["manifest_path"] = os.path.abspath(manifest_path)
    return payload


def _serialize_manifest_source(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "log_file": os.path.abspath(str(source.get("log_file") or "")) if str(source.get("log_file") or "").strip() else "",
        "run_id": str(source.get("run_id") or ""),
        "split_role": _normalize_split_role(source.get("split_role") or ""),
        "source_profile": str(source.get("source_profile") or ""),
        "training_pool": bool(source.get("training_pool", True)),
        "bootstrap_only": bool(source.get("bootstrap_only", False)),
        "phases": list(source.get("phases") or []),
    }


def _build_manifest_record(
    window_id: str,
    window_path: str,
    g,
    *,
    source_log_file: str = "",
    source_run_id: str = "",
    source_profile: str = "",
    source_phase_id: str = "",
    split_role: str = "",
    window_start_ns: int = 0,
    window_end_ns: int = 0,
    window_sequence: int = 0,
) -> dict[str, Any]:
    """从窗口图提取训练/校准阶段需要的最小元数据"""

    node_count = int(g.number_of_nodes())
    edge_count = int(g.number_of_edges())
    process_node_count = sum(1 for node_id in g.nodes() if str(node_id).startswith("proc:"))
    return {
        "window_id": window_id,
        "path": os.path.abspath(window_path),
        "node_count": node_count,
        "edge_count": edge_count,
        "process_node_count": int(process_node_count),
        "trainable": bool(node_count > 0),
        "scorable": bool(node_count > 0 and process_node_count > 0),
        "source_log_file": os.path.abspath(source_log_file) if str(source_log_file or "").strip() else "",
        "source_run_id": str(source_run_id or ""),
        "source_profile": str(source_profile or ""),
        "source_phase_id": str(source_phase_id or ""),
        "split_role": _normalize_split_role(split_role or ""),
        "window_start_ns": int(window_start_ns or 0),
        "window_end_ns": int(window_end_ns or 0),
        "window_sequence": int(window_sequence or 0),
    }


def _summarize_manifest_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    trainable_records = [record for record in records if bool(record.get("trainable"))]
    scorable_records = [record for record in records if bool(record.get("scorable"))]
    processless_trainable_records = [
        record for record in trainable_records if not bool(record.get("scorable"))
    ]
    source_run_ids = sorted(
        {
            str(record.get("source_run_id") or "").strip()
            for record in records
            if str(record.get("source_run_id") or "").strip()
        }
    )
    profile_counter = Counter(
        _profile_label(record.get("source_profile"))
        for record in records
        if bool(record.get("trainable"))
    )
    split_role_counter = Counter(
        _normalize_split_role(record.get("split_role") or "") or "train"
        for record in records
    )
    return {
        "window_count": int(len(records)),
        "trainable_window_count": int(len(trainable_records)),
        "scorable_window_count": int(len(scorable_records)),
        "empty_window_count": int(sum(1 for record in records if not bool(record.get("trainable")))),
        "processless_trainable_window_count": int(len(processless_trainable_records)),
        "node_count_sum": int(sum(int(record.get("node_count") or 0) for record in records)),
        "edge_count_sum": int(sum(int(record.get("edge_count") or 0) for record in records)),
        "process_node_count_sum": int(sum(int(record.get("process_node_count") or 0) for record in records)),
        "unique_source_run_count": int(len(source_run_ids)),
        "source_run_ids": source_run_ids,
        "profile_window_distribution": dict(sorted(profile_counter.items())),
        "split_role_window_distribution": dict(sorted(split_role_counter.items())),
    }


def _split_gmae_manifest(
    records: list[dict[str, Any]],
    seed: int,
    calibration_ratio: float,
    source_mode: str = "",
) -> dict[str, Any]:
    if str(source_mode or "") == "logs_dir":
        return _split_gmae_manifest_run_level(records, seed=seed)
    return _split_gmae_manifest_window_level(records, seed=seed, calibration_ratio=calibration_ratio)


def _split_gmae_manifest_window_level(
    records: list[dict[str, Any]],
    seed: int,
    calibration_ratio: float,
) -> dict[str, Any]:
    """按稳定随机规则切 train/calibration。

    只有 `scorable` 窗口参与 calibration 抽样。
    非空但没有进程节点的窗口仍然保留在 train 中，以便参与参数更新。
    """

    scorable_records = sorted(
        [record for record in records if bool(record.get("scorable"))],
        key=lambda item: str(item.get("window_id") or ""),
    )
    calibration_candidates = list(scorable_records)
    random.Random(seed).shuffle(calibration_candidates)

    calibration_count = int(math.floor(len(calibration_candidates) * float(calibration_ratio)))
    # 至少保留一个 scorable 窗口在 train 中，否则无法完成训练。
    calibration_count = min(calibration_count, max(len(calibration_candidates) - 1, 0))
    calibration_ids = {
        str(record.get("window_id") or "")
        for record in calibration_candidates[:calibration_count]
    }

    train_records = [
        record
        for record in records
        if bool(record.get("trainable")) and str(record.get("window_id") or "") not in calibration_ids
    ]
    empty_records = [record for record in records if not bool(record.get("trainable"))]
    calibration_records = [
        record for record in records if str(record.get("window_id") or "") in calibration_ids
    ]

    source_run_ids = _unique_source_run_ids(records)
    summary = {
        "split_strategy": "window_random",
        "seed": int(seed),
        "calibration_ratio": float(calibration_ratio),
        "window_count": int(len(records)),
        "trainable_window_count": int(sum(1 for record in records if bool(record.get("trainable")))),
        "scorable_window_count": int(len(scorable_records)),
        "train_window_count": int(len(train_records)),
        "calibration_window_count": int(len(calibration_records)),
        "holdout_window_count": 0,
        "empty_window_count": int(len(empty_records)),
        "calibration_unsuitable_window_count": 0,
        "train_window_ids": [str(record.get("window_id") or "") for record in train_records],
        "calibration_window_ids": [str(record.get("window_id") or "") for record in calibration_records],
        "holdout_window_ids": [],
        "scorable_window_ids": [str(record.get("window_id") or "") for record in scorable_records],
        "empty_window_ids": [str(record.get("window_id") or "") for record in empty_records],
        "source_run_ids": source_run_ids,
        "training_source_run_ids": source_run_ids,
        "train_run_ids": source_run_ids,
        "calibration_run_ids": [],
        "holdout_run_ids": [],
        "unique_source_run_count": int(len(source_run_ids)),
        "profile_window_distribution": _profile_window_distribution(train_records),
        "split_role_window_distribution": {"train": int(len(records))},
    }
    return {
        "train_records": train_records,
        "calibration_records": calibration_records,
        "empty_records": empty_records,
        "summary": summary,
    }


def _split_gmae_manifest_run_level(records: list[dict[str, Any]], seed: int) -> dict[str, Any]:
    role_records: dict[str, list[dict[str, Any]]] = {"train": [], "calibration": [], "holdout": []}
    for record in records:
        role = _normalize_split_role(record.get("split_role") or "") or "train"
        role_records.setdefault(role, []).append(record)

    train_records = [record for record in role_records["train"] if bool(record.get("trainable"))]
    empty_records = [record for record in role_records["train"] if not bool(record.get("trainable"))]
    calibration_records = [record for record in role_records["calibration"] if bool(record.get("scorable"))]
    calibration_unsuitable_records = [
        record for record in role_records["calibration"] if not bool(record.get("scorable"))
    ]
    holdout_records = [record for record in role_records["holdout"] if bool(record.get("trainable"))]
    scorable_records = sorted(
        [
            record
            for record in records
            if bool(record.get("scorable")) and _normalize_split_role(record.get("split_role") or "") != "holdout"
        ],
        key=lambda item: str(item.get("window_id") or ""),
    )

    train_run_ids = _unique_source_run_ids(role_records["train"])
    calibration_run_ids = _unique_source_run_ids(role_records["calibration"])
    holdout_run_ids = _unique_source_run_ids(role_records["holdout"])
    training_source_run_ids = sorted(set(train_run_ids) | set(calibration_run_ids))
    source_run_ids = sorted(set(training_source_run_ids) | set(holdout_run_ids))
    split_role_counter = Counter(
        _normalize_split_role(record.get("split_role") or "") or "train"
        for record in records
    )

    summary = {
        "split_strategy": "run_level",
        "seed": int(seed),
        "calibration_ratio": None,
        "window_count": int(len(records)),
        "trainable_window_count": int(sum(1 for record in records if bool(record.get("trainable")))),
        "scorable_window_count": int(len(scorable_records)),
        "train_window_count": int(len(train_records)),
        "calibration_window_count": int(len(calibration_records)),
        "holdout_window_count": int(len(holdout_records)),
        "empty_window_count": int(len(empty_records)),
        "calibration_unsuitable_window_count": int(len(calibration_unsuitable_records)),
        "train_window_ids": [str(record.get("window_id") or "") for record in train_records],
        "calibration_window_ids": [str(record.get("window_id") or "") for record in calibration_records],
        "holdout_window_ids": [str(record.get("window_id") or "") for record in holdout_records],
        "scorable_window_ids": [str(record.get("window_id") or "") for record in scorable_records],
        "empty_window_ids": [str(record.get("window_id") or "") for record in empty_records],
        "source_run_ids": source_run_ids,
        "training_source_run_ids": training_source_run_ids,
        "train_run_ids": train_run_ids,
        "calibration_run_ids": calibration_run_ids,
        "holdout_run_ids": holdout_run_ids,
        "unique_source_run_count": int(len(training_source_run_ids)),
        "profile_window_distribution": _profile_window_distribution(train_records),
        "split_role_window_distribution": dict(sorted(split_role_counter.items())),
    }
    return {
        "train_records": train_records,
        "calibration_records": calibration_records,
        "empty_records": empty_records,
        "holdout_records": holdout_records,
        "summary": summary,
    }


def _unique_source_run_ids(records: Iterable[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            str(record.get("source_run_id") or "").strip()
            for record in records
            if str(record.get("source_run_id") or "").strip()
        }
    )


def _profile_label(value: Any) -> str:
    text = str(value or "").strip()
    return text if text else "unknown"


def _profile_window_distribution(records: Iterable[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(_profile_label(record.get("source_profile")) for record in records if bool(record.get("trainable", True)))
    return dict(sorted(counter.items()))


def _evaluate_training_quality(
    manifest_payload: dict[str, Any],
    split_summary: dict[str, Any],
) -> dict[str, Any]:
    source_mode = str(manifest_payload.get("source_mode") or "")
    split_strategy = str(split_summary.get("split_strategy") or "")
    training_tier = "formal" if source_mode == "logs_dir" and split_strategy == "run_level" else "bootstrap"
    errors: list[str] = []

    if training_tier == "formal":
        train_window_count = int(split_summary.get("train_window_count") or 0)
        calibration_window_count = int(split_summary.get("calibration_window_count") or 0)
        unique_source_run_count = int(split_summary.get("unique_source_run_count") or 0)
        if train_window_count < DEFAULT_BBK_MIN_TRAIN_WINDOWS:
            errors.append(
                f"trainable benign windows below threshold: {train_window_count} < {DEFAULT_BBK_MIN_TRAIN_WINDOWS}"
            )
        if calibration_window_count < DEFAULT_BBK_MIN_CALIBRATION_WINDOWS:
            errors.append(
                "calibration benign windows below threshold: "
                f"{calibration_window_count} < {DEFAULT_BBK_MIN_CALIBRATION_WINDOWS}"
            )
        if unique_source_run_count < DEFAULT_BBK_MIN_SOURCE_RUNS:
            errors.append(
                f"unique benign source runs below threshold: {unique_source_run_count} < {DEFAULT_BBK_MIN_SOURCE_RUNS}"
            )

    imbalance_warning = _build_profile_imbalance_warning(
        dict(split_summary.get("profile_window_distribution") or {}),
        total_windows=int(split_summary.get("train_window_count") or 0),
    )
    return {
        "training_tier": training_tier,
        "errors": errors,
        "imbalance_warning": imbalance_warning,
    }


def _build_profile_imbalance_warning(
    profile_window_distribution: dict[str, int],
    *,
    total_windows: int,
) -> dict[str, Any] | None:
    if total_windows <= 0 or not profile_window_distribution:
        return None

    offenders = []
    for profile_id, count in sorted(profile_window_distribution.items()):
        ratio = float(count) / float(total_windows)
        if ratio > float(DEFAULT_BBK_PROFILE_IMBALANCE_RATIO):
            offenders.append(
                {
                    "source_profile": str(profile_id),
                    "window_count": int(count),
                    "ratio": float(ratio),
                }
            )

    if not offenders:
        return None
    return {
        "threshold_ratio": float(DEFAULT_BBK_PROFILE_IMBALANCE_RATIO),
        "train_window_count": int(total_windows),
        "offenders": offenders,
    }


def _epoch_train_order(records: list[dict[str, Any]], seed: int, epoch: int) -> list[dict[str, Any]]:
    """生成某个 epoch 的训练顺序。"""

    ordered = sorted(records, key=lambda item: str(item.get("window_id") or ""))
    random.Random(seed + epoch).shuffle(ordered)
    return ordered


def _new_loss_trackers() -> dict[str, RunningStats]:
    return {
        "total_loss": RunningStats(),
        "node_recon_loss": RunningStats(),
        "structure_loss": RunningStats(),
    }


def _update_loss_trackers(trackers: dict[str, RunningStats], losses: dict[str, float]) -> None:
    trackers["total_loss"].update(float(losses["total_loss"]))
    trackers["node_recon_loss"].update(float(losses["node_recon_loss"]))
    trackers["structure_loss"].update(float(losses["structure_loss"]))


def _increment_skip_counters(
    global_counters: dict[str, int],
    epoch_counters: dict[str, int],
    skip_kind: str,
) -> None:
    if skip_kind == "empty":
        global_counters["skipped_empty_windows"] += 1
        epoch_counters["skipped_empty_windows"] += 1
        return
    if skip_kind == "nonfinite":
        global_counters["skipped_nonfinite_windows"] += 1
        epoch_counters["skipped_nonfinite_windows"] += 1
        return
    global_counters["failed_windows"] += 1
    epoch_counters["failed_windows"] += 1


def _append_debug_history(
    history: deque[dict[str, Any]],
    epoch: int,
    window_id: str,
    skipped: bool,
    reason: str,
    losses: Optional[dict[str, float]],
) -> None:
    """只保留有限长度的窗口级调试记录，避免训练期元数据无限增长。"""

    history.append(
        {
            "epoch": int(epoch),
            "window_id": str(window_id),
            "total_loss": _safe_debug_float(None if not losses else losses.get("total_loss")),
            "node_recon_loss": _safe_debug_float(None if not losses else losses.get("node_recon_loss")),
            "structure_loss": _safe_debug_float(None if not losses else losses.get("structure_loss")),
            "skipped": bool(skipped),
            "reason": _short_reason(reason, limit=96) if reason else "",
        }
    )


def _empty_distribution_summary() -> dict[str, Any]:
    return {
        "count": 0,
        "mean": None,
        "std": None,
        "min": None,
        "max": None,
        "p95": None,
        "p99": None,
    }


def _summarize_distribution(values: list[float]) -> dict[str, Any]:
    if not values:
        return _empty_distribution_summary()

    stats = RunningStats()
    for value in values:
        stats.update(float(value))
    payload = stats.to_dict()
    payload["p95"] = _percentile(values, 0.95)
    payload["p99"] = _percentile(values, 0.99)
    return payload


def _percentile(sorted_values: list[float], q: float) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return float(sorted_values[0])

    position = (len(sorted_values) - 1) * float(q)
    lower_idx = int(math.floor(position))
    upper_idx = int(math.ceil(position))
    if lower_idx == upper_idx:
        return float(sorted_values[lower_idx])

    lower_val = float(sorted_values[lower_idx])
    upper_val = float(sorted_values[upper_idx])
    weight = position - lower_idx
    return float(lower_val * (1.0 - weight) + upper_val * weight)


def _clone_state_dict_to_cpu(state_dict: dict[str, Any]) -> dict[str, Any]:
    """冻结当前 checkpoint，避免后续训练继续原地修改同一组张量。"""

    cloned: dict[str, Any] = {}
    for key, value in state_dict.items():
        if hasattr(value, "detach"):
            cloned[key] = value.detach().cpu().clone()
        else:
            cloned[key] = copy.deepcopy(value)
    return cloned


def _stable_step_seed(base_seed: int, epoch: int, window_id: str) -> int:
    """把 run seed + epoch + window_id 映射成稳定的窗口级随机种子。"""

    digest = hashlib.blake2b(
        f"{base_seed}:{epoch}:{window_id}".encode("utf-8"),
        digest_size=8,
    ).digest()
    return int.from_bytes(digest, "little") & 0x7FFFFFFF


def _seed_torch(torch_module, seed: int) -> None:
    torch_module.manual_seed(int(seed))
    if torch_module.cuda.is_available():
        torch_module.cuda.manual_seed_all(int(seed))
        if hasattr(torch_module.backends, "cudnn"):
            torch_module.backends.cudnn.deterministic = True
            torch_module.backends.cudnn.benchmark = False


def _is_finite_tensor(torch_module, value) -> bool:
    try:
        return bool(torch_module.isfinite(value.detach()).all().item())
    except Exception:
        return False


def _tensor_to_float(value) -> float | None:
    try:
        return float(value.detach().cpu().item())
    except Exception:
        return None


def _safe_debug_float(value: Any) -> float | None:
    try:
        return None if value is None else float(value)
    except Exception:
        return None


def _short_reason(reason: str, limit: int = 120) -> str:
    text = " ".join(str(reason or "").split())
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 0)] + "..."


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return int(default)
    try:
        return int(raw)
    except ValueError:
        return int(default)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return float(default)
    try:
        return float(raw)
    except ValueError:
        return float(default)
