#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import json
import math
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Sequence

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.common.defaults import (
    DEFAULT_BBK_TRAIN_WINDOW_SECONDS,
    DEFAULT_BENIGN_CORPUS_DIR,
    DEFAULT_TIME_BIN_SECONDS,
)
from src.common.io import read_json, write_json


DEFAULT_CONFIG_PATH = ROOT_DIR / "config" / "benign_corpus.default.json"
DEFAULT_TRACEE_IMAGE = "aquasec/tracee:latest"
DEFAULT_EVENTS = [
    "sched_process_exec",
    "execve",
    "openat",
    "read",
    "write",
    "close",
    "connect",
    "accept",
    "sendto",
    "recvfrom",
    "fork",
    "clone",
    "vfork",
    "mmap",
    "security_socket_connect",
    "security_socket_accept",
]
DEFAULT_CORPUS_VERSION = "v3"


def run_cmd(
    args: Sequence[str],
    *,
    capture: bool = True,
    check: bool = True,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=str(ROOT_DIR),
        text=True,
        capture_output=capture,
        check=check,
        timeout=timeout,
    )


def load_profile_module(module_name: str):
    module = importlib.import_module(str(module_name))
    if not hasattr(module, "run_profile"):
        raise RuntimeError(f"profile module missing run_profile(): {module_name}")
    if not hasattr(module, "profile_catalog"):
        raise RuntimeError(f"profile module missing profile_catalog(): {module_name}")
    return module


def wait_for_health(health_url: str, timeout_seconds: int) -> None:
    deadline = time.time() + int(timeout_seconds)
    last_error = ""
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(str(health_url), timeout=5) as resp:
                if 200 <= int(resp.status) < 500:
                    return
        except Exception as exc:
            last_error = str(exc)
        time.sleep(1)
    raise RuntimeError(f"target service did not become reachable: {health_url} ({last_error})")


def tracee_command(trace_path: Path, tracee_name: str, config: dict[str, Any]) -> list[str]:
    tracee_cfg = dict(config.get("tracee") or {})
    events = list(tracee_cfg.get("events") or DEFAULT_EVENTS)
    scopes = list(tracee_cfg.get("scopes") or ["container", "comm!=tracee"])
    image = str(tracee_cfg.get("image") or DEFAULT_TRACEE_IMAGE)

    cmd = [
        "docker",
        "run",
        "--name",
        tracee_name,
        "--rm",
        "-i",
        "--privileged",
        "--pid=host",
        "--cgroupns=host",
        "--network=host",
        "-v",
        "/lib/modules:/lib/modules:ro",
        "-v",
        "/usr/src:/usr/src:ro",
        "-v",
        "/etc/os-release:/etc/os-release-host:ro",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        "/sys/fs/cgroup:/sys/fs/cgroup:ro",
        image,
        "--containers",
        "enrich=true",
        "--containers",
        "sockets.docker=/var/run/docker.sock",
        "--containers",
        "cgroupfs.path=/sys/fs/cgroup",
        "--containers",
        "cgroupfs.force=true",
    ]
    for scope in scopes:
        cmd.extend(["--scope", str(scope)])
    cmd.extend(
        [
            "--events",
            ",".join(str(item) for item in events),
            "--output",
            "table",
            "--output",
            "option:parse-arguments",
        ]
    )
    return cmd


def start_tracee(trace_path: Path, tracee_name: str, config: dict[str, Any]) -> tuple[subprocess.Popen[str], Any]:
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    trace_fp = trace_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        tracee_command(trace_path, tracee_name, config),
        cwd=str(ROOT_DIR),
        stdout=trace_fp,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc, trace_fp


def stop_tracee(tracee_proc: subprocess.Popen[str], tracee_name: str, trace_fp: Any) -> None:
    run_cmd(["docker", "rm", "-f", tracee_name], capture=True, check=False)
    try:
        tracee_proc.wait(timeout=20)
    except Exception:
        tracee_proc.kill()
    trace_fp.close()


def normalize_driver_roles(phase: dict[str, Any], default_driver_roles: Sequence[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    phase_profile_id = str(phase.get("profile_id") or "").strip()
    raw_roles = list(phase.get("driver_roles") or default_driver_roles or [])
    if not raw_roles:
        raw_roles = [
            {"driver_role": "foreground_user", "profile_id": "$phase"},
            {"driver_role": "background_worker", "profile_id": "background_worker"},
        ]

    roles: list[dict[str, Any]] = []
    seen = set()
    for raw in raw_roles:
        if not isinstance(raw, dict):
            raise ValueError(f"driver role entry must be an object: {raw!r}")
        driver_role = str(raw.get("driver_role") or raw.get("role") or "").strip()
        if not driver_role:
            raise ValueError(f"driver_role is required for phase profile={phase_profile_id}")
        profile_id = str(raw.get("profile_id") or "").strip()
        if not profile_id or profile_id == "$phase":
            profile_id = phase_profile_id
        key = (driver_role, profile_id)
        if key in seen:
            continue
        seen.add(key)
        roles.append({"driver_role": driver_role, "profile_id": profile_id})
    return roles


def normalize_phases(run: dict[str, Any], default_driver_roles: Sequence[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    phases = []
    start_offset = 0.0
    for idx, phase in enumerate(list(run.get("phases") or []), start=1):
        duration = int(phase.get("duration_seconds") or 0)
        if duration <= 0:
            raise ValueError(f"invalid phase duration in run={run.get('run_id')}: {duration}")
        profile_id = str(phase.get("profile_id") or "").strip()
        if not profile_id:
            raise ValueError(f"missing profile_id in run={run.get('run_id')}")
        end_offset = start_offset + float(duration)
        phases.append(
            {
                "phase_id": str(phase.get("phase_id") or f"{run.get('run_id')}_phase_{idx:02d}"),
                "profile_id": profile_id,
                "start_offset_seconds": float(start_offset),
                "end_offset_seconds": float(end_offset),
                "duration_seconds": int(duration),
                "driver_roles": normalize_driver_roles(phase, default_driver_roles),
            }
        )
        start_offset = end_offset
    return phases


def expected_distribution(config: dict[str, Any]) -> dict[str, Any]:
    window_seconds = int(config.get("window_seconds") or DEFAULT_BBK_TRAIN_WINDOW_SECONDS)
    time_bin_seconds = int(config.get("time_bin_seconds") or DEFAULT_TIME_BIN_SECONDS)
    default_driver_roles = list(config.get("driver_roles") or [])
    run_summaries = []
    profile_windows: dict[str, int] = {}
    role_windows: dict[str, int] = {}
    driver_role_windows: dict[str, int] = {}
    train_profile_windows: dict[str, int] = {}
    for run in list(config.get("runs") or []):
        phases = normalize_phases(run, default_driver_roles)
        role = str(run.get("split_role") or "train")
        run_windows = 0
        for phase in phases:
            windows = int(math.floor(float(phase["duration_seconds"]) / float(window_seconds)))
            run_windows += windows
            profile_id = str(phase["profile_id"])
            profile_windows[profile_id] = int(profile_windows.get(profile_id, 0)) + windows
            for driver_role in list(phase.get("driver_roles") or []):
                role_id = str(driver_role.get("driver_role") or "")
                if role_id:
                    driver_role_windows[role_id] = int(driver_role_windows.get(role_id, 0)) + windows
            if role == "train":
                train_profile_windows[profile_id] = int(train_profile_windows.get(profile_id, 0)) + windows
        role_windows[role] = int(role_windows.get(role, 0)) + run_windows
        run_summaries.append(
            {
                "run_id": str(run.get("run_id") or ""),
                "split_role": role,
                "duration_seconds": int(sum(int(phase["duration_seconds"]) for phase in phases)),
                "expected_windows": int(run_windows),
                "phases": phases,
            }
        )

    train_total = int(role_windows.get("train", 0))
    profile_imbalance = {
        profile_id: float(count) / float(train_total)
        for profile_id, count in sorted(train_profile_windows.items())
        if train_total > 0
    }
    return {
        "window_seconds": int(window_seconds),
        "time_bin_seconds": int(time_bin_seconds),
        "total_expected_windows": int(sum(role_windows.values())),
        "role_expected_windows": dict(sorted(role_windows.items())),
        "driver_role_expected_windows": dict(sorted(driver_role_windows.items())),
        "profile_expected_windows": dict(sorted(profile_windows.items())),
        "train_profile_expected_windows": dict(sorted(train_profile_windows.items())),
        "train_profile_imbalance": profile_imbalance,
        "validation_targets": dict(config.get("validation_targets") or {}),
        "runs": run_summaries,
    }


def validate_distribution(summary: dict[str, Any]) -> list[str]:
    errors = []
    role_windows = dict(summary.get("role_expected_windows") or {})
    profile_windows = dict(summary.get("profile_expected_windows") or {})
    train_imbalance = dict(summary.get("train_profile_imbalance") or {})
    targets = dict(summary.get("validation_targets") or {})
    min_train_windows = int(targets.get("min_train_windows", 200))
    min_calibration_windows = int(targets.get("min_calibration_windows", 50))
    min_holdout_windows = int(targets.get("min_holdout_windows", 80))
    min_profile_windows = int(targets.get("min_profile_windows", 50))
    max_train_profile_ratio = float(targets.get("max_train_profile_ratio", 0.4))
    if int(role_windows.get("train", 0)) < min_train_windows:
        errors.append(f"expected train windows below target: < {min_train_windows}")
    if int(role_windows.get("calibration", 0)) < min_calibration_windows:
        errors.append(f"expected calibration windows below target: < {min_calibration_windows}")
    if int(role_windows.get("holdout", 0)) < min_holdout_windows:
        errors.append(f"expected holdout windows below target: < {min_holdout_windows}")
    for profile_id, count in sorted(profile_windows.items()):
        if int(count) < min_profile_windows:
            errors.append(f"profile expected windows below target: {profile_id}={count} < {min_profile_windows}")
    for profile_id, ratio in sorted(train_imbalance.items()):
        if float(ratio) > max_train_profile_ratio:
            errors.append(f"train profile imbalance above target: {profile_id}={ratio:.3f} > {max_train_profile_ratio:.3f}")
    return errors


def validate_profile_catalog(config: dict[str, Any], profile_module) -> list[str]:
    catalog = dict(profile_module.profile_catalog())
    known = set(str(key) for key in catalog)
    errors = []
    default_driver_roles = list(config.get("driver_roles") or [])
    for run in list(config.get("runs") or []):
        for phase in normalize_phases(run, default_driver_roles):
            profile_id = str(phase["profile_id"])
            if profile_id not in known:
                errors.append(f"unknown profile_id in config: {profile_id}")
            for role in list(phase.get("driver_roles") or []):
                role_profile_id = str(role.get("profile_id") or "")
                driver_role = str(role.get("driver_role") or "")
                if driver_role == "background_worker" and role_profile_id == "background_worker":
                    continue
                if role_profile_id not in known:
                    errors.append(f"unknown role profile_id in config: {role_profile_id}")
    prewarm_profile = str(config.get("prewarm_profile") or "")
    if prewarm_profile and prewarm_profile not in known:
        errors.append(f"unknown prewarm_profile in config: {prewarm_profile}")
    return errors


def _metric_counter_payload() -> dict[str, int]:
    return {
        "request_count": 0,
        "success_count": 0,
        "http_error_count": 0,
        "exception_count": 0,
        "timeout_count": 0,
    }


def _add_metric_counts(dst: dict[str, Any], src: dict[str, Any]) -> None:
    for key in ("request_count", "success_count", "http_error_count", "exception_count", "timeout_count"):
        dst[key] = int(dst.get(key, 0)) + int(src.get(key, 0) or 0)


def summarize_driver_metrics(role_metrics: list[dict[str, Any]]) -> dict[str, Any]:
    aggregate: dict[str, Any] = _metric_counter_payload()
    by_role_profile: dict[str, dict[str, Any]] = {}
    by_profile: dict[str, dict[str, Any]] = {}
    by_phase: dict[str, dict[str, Any]] = {}
    for raw in role_metrics:
        metric = dict(raw or {})
        _add_metric_counts(aggregate, metric)
        driver_role = str(metric.get("driver_role") or "")
        profile_id = str(metric.get("profile_id") or "")
        phase_id = str(metric.get("phase_id") or "")
        role_profile_key = f"{driver_role}:{profile_id}"
        _add_metric_counts(by_role_profile.setdefault(role_profile_key, _metric_counter_payload()), metric)
        _add_metric_counts(by_profile.setdefault(profile_id, _metric_counter_payload()), metric)
        _add_metric_counts(by_phase.setdefault(phase_id, _metric_counter_payload()), metric)

    return {
        "schema_version": 1,
        "metric_type": "benign_driver_request_metrics",
        "aggregate": aggregate,
        "by_role_profile": dict(sorted(by_role_profile.items())),
        "by_profile": dict(sorted(by_profile.items())),
        "by_phase": dict(sorted(by_phase.items())),
        "role_metrics": role_metrics,
    }


def run_phases(
    *,
    profile_module,
    phases: list[dict[str, Any]],
    base_url: str,
    seed: int,
    log_path: Path,
    metrics_path: Path | None = None,
) -> dict[str, Any]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    role_metrics: list[dict[str, Any]] = []
    with log_path.open("w", encoding="utf-8") as fp:
        for idx, phase in enumerate(phases, start=1):
            duration = float(phase["duration_seconds"])
            phase_seed = int(seed) + idx
            fp.write(f"phase_start id={phase['phase_id']} profile={phase['profile_id']} duration={duration} seed={phase_seed}\n")
            fp.flush()
            lock = threading.Lock()
            errors: list[BaseException] = []
            threads: list[threading.Thread] = []

            def run_role(role_cfg: dict[str, Any], role_idx: int) -> None:
                driver_role = str(role_cfg.get("driver_role") or "foreground_user")
                role_profile_id = str(role_cfg.get("profile_id") or phase["profile_id"])
                role_seed = int(phase_seed) * 100 + int(role_idx)
                try:
                    with lock:
                        fp.write(
                            f"role_start phase={phase['phase_id']} role={driver_role} "
                            f"profile={role_profile_id} duration={duration} seed={role_seed}\n"
                        )
                        fp.flush()
                    if driver_role == "background_worker" and hasattr(profile_module, "run_background_worker"):
                        result = profile_module.run_background_worker(
                            base_url=str(base_url),
                            duration_seconds=duration,
                            seed=role_seed,
                            phase_profile_id=str(phase["profile_id"]),
                        )
                    else:
                        result = profile_module.run_profile(
                            role_profile_id,
                            base_url=str(base_url),
                            duration_seconds=duration,
                            seed=role_seed,
                        )
                    metrics_payload = result if isinstance(result, dict) else {}
                    metrics_payload.update(
                        {
                            "phase_id": str(phase["phase_id"]),
                            "phase_profile_id": str(phase["profile_id"]),
                            "driver_role": driver_role,
                            "profile_id": role_profile_id,
                            "seed": int(role_seed),
                        }
                    )
                    with lock:
                        role_metrics.append(dict(metrics_payload))
                        fp.write(
                            "role_metrics "
                            + json.dumps(metrics_payload, ensure_ascii=False, sort_keys=True)
                            + "\n"
                        )
                        fp.flush()
                    with lock:
                        fp.write(f"role_end phase={phase['phase_id']} role={driver_role} profile={role_profile_id}\n")
                        fp.flush()
                except BaseException as exc:
                    with lock:
                        errors.append(exc)

            role_configs = list(phase.get("driver_roles") or [{"driver_role": "foreground_user", "profile_id": phase["profile_id"]}])
            for role_idx, role_cfg in enumerate(role_configs, start=1):
                thread = threading.Thread(target=run_role, args=(dict(role_cfg), role_idx), daemon=True)
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join()
            if errors:
                raise RuntimeError(f"phase failed: {phase['phase_id']} ({errors[0]})") from errors[0]
            fp.write(f"phase_end id={phase['phase_id']} profile={phase['profile_id']}\n")
            fp.flush()
    summary = summarize_driver_metrics(role_metrics)
    if metrics_path is not None:
        write_json(str(metrics_path), summary)
    return summary


def _phase_role_schedule(phases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    schedule: list[dict[str, Any]] = []
    for phase in phases:
        for role_cfg in list(phase.get("driver_roles") or []):
            schedule.append(
                {
                    "phase_id": str(phase.get("phase_id") or ""),
                    "profile_id": str(phase.get("profile_id") or ""),
                    "driver_role": str(role_cfg.get("driver_role") or ""),
                    "role_profile_id": str(role_cfg.get("profile_id") or ""),
                    "start_offset_seconds": float(phase.get("start_offset_seconds") or 0.0),
                    "end_offset_seconds": float(phase.get("end_offset_seconds") or 0.0),
                    "duration_seconds": int(phase.get("duration_seconds") or 0),
                }
            )
    return schedule


def collect_run(
    *,
    config: dict[str, Any],
    profile_module,
    corpus_dir: Path,
    run: dict[str, Any],
    base_seed: int,
) -> dict[str, Any]:
    target = dict(config.get("target") or {})
    base_url = str(target.get("base_url") or "").rstrip("/")
    health_url = str(target.get("health_url") or (base_url + "/health"))
    if not base_url:
        raise ValueError("target.base_url is required")

    run_id = str(run.get("run_id") or "").strip()
    if not run_id:
        raise ValueError("run_id is required")
    default_driver_roles = list(config.get("driver_roles") or [])
    phases = normalize_phases(run, default_driver_roles)
    run_dir = corpus_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    trace_path = run_dir / "trace.log"
    driver_log_path = run_dir / "driver.log"
    driver_metrics_path = run_dir / "driver_metrics.json"
    prewarm_log_path = run_dir / "prewarm.log"
    prewarm_metrics_path = run_dir / "prewarm_driver_metrics.json"
    run_meta_path = run_dir / "run_meta.json"

    wait_for_health(health_url, timeout_seconds=int(target.get("health_timeout_seconds") or 60))
    prewarm_seconds = int(config.get("prewarm_seconds") or 0)
    prewarm_profile = str(config.get("prewarm_profile") or phases[0]["profile_id"])
    prewarm_metrics: dict[str, Any] = {}
    if prewarm_seconds > 0:
        prewarm_phases = normalize_phases(
            {
                "run_id": run_id,
                "phases": [
                    {
                        "phase_id": f"{run_id}_prewarm",
                        "profile_id": prewarm_profile,
                        "duration_seconds": int(prewarm_seconds),
                        "driver_roles": [{"driver_role": "foreground_user", "profile_id": prewarm_profile}],
                    }
                ],
            },
            default_driver_roles=[],
        )
        run_phases(
            profile_module=profile_module,
            phases=prewarm_phases,
            base_url=base_url,
            seed=int(base_seed),
            log_path=prewarm_log_path,
            metrics_path=prewarm_metrics_path,
        )
        prewarm_metrics = read_json(str(prewarm_metrics_path)) or {}

    tracee_name = f"drsec-tracee-benign-corpus-{run_id}"
    run_cmd(["docker", "rm", "-f", tracee_name], capture=True, check=False)
    tracee_proc, trace_fp = start_tracee(trace_path, tracee_name, config)
    try:
        time.sleep(float(config.get("tracee_settle_seconds") or 3.0))
        driver_metrics = run_phases(
            profile_module=profile_module,
            phases=phases,
            base_url=base_url,
            seed=int(base_seed),
            log_path=driver_log_path,
            metrics_path=driver_metrics_path,
        )
        time.sleep(float(config.get("tracee_flush_seconds") or 3.0))
    finally:
        stop_tracee(tracee_proc, tracee_name, trace_fp)

    split_role = str(run.get("split_role") or "train")
    split_semantics = {
        "train": "BBK/GMAE training only; do not report final benign FPR on this split.",
        "calibration": "Threshold or score calibration only; do not train GMAE on this split.",
        "holdout": "Final benign false-positive evaluation only; do not use for training, calibration, or threshold selection.",
    }
    container_roles = dict(config.get("container_roles") or {})
    trace_scope = dict(config.get("trace_scope") or {})
    if not trace_scope:
        trace_scope = {
            "scope_expression": list((config.get("tracee") or {}).get("scopes") or []),
            "events": list((config.get("tracee") or {}).get("events") or []),
        }
    payload = {
        "schema_version": 3,
        "corpus_version": str(config.get("corpus_version") or DEFAULT_CORPUS_VERSION),
        "run_id": run_id,
        "kind": "benign_corpus_run",
        "split_role": split_role,
        "split_semantics": split_semantics.get(split_role, ""),
        "target_service": str(target.get("name") or ""),
        "target_base_url": base_url,
        "target_container": dict(container_roles.get("target_container") or {}),
        "supporting_containers": list(container_roles.get("supporting_containers") or []),
        "driver_host": dict(container_roles.get("driver_host") or {}),
        "trace_scope": trace_scope,
        "trace_out": str(trace_path),
        "driver_log": str(driver_log_path),
        "driver_metrics": str(driver_metrics_path),
        "driver_metrics_summary": dict((driver_metrics or {}).get("aggregate") or {}),
        "prewarm_log": str(prewarm_log_path),
        "prewarm_driver_metrics": str(prewarm_metrics_path),
        "prewarm_driver_metrics_summary": dict((prewarm_metrics or {}).get("aggregate") or {}),
        "duration_seconds": int(sum(int(phase["duration_seconds"]) for phase in phases)),
        "prewarm_seconds": int(prewarm_seconds),
        "random_seed": int(base_seed),
        "training_pool": bool(run.get("training_pool", True)),
        "bootstrap_only": bool(run.get("bootstrap_only", False)),
        "window_seconds": int(config.get("window_seconds") or DEFAULT_BBK_TRAIN_WINDOW_SECONDS),
        "time_bin_seconds": int(config.get("time_bin_seconds") or DEFAULT_TIME_BIN_SECONDS),
        "driver_roles": list(config.get("driver_roles") or []),
        "phases": phases,
        "phase_role_schedule": _phase_role_schedule(phases),
        "profile_ids": [str(phase["profile_id"]) for phase in phases],
    }
    write_json(str(run_meta_path), payload)
    return payload


def write_corpus_manifest(
    *,
    corpus_dir: Path,
    config: dict[str, Any],
    profile_module,
    run_metas: list[dict[str, Any]],
    distribution: dict[str, Any],
) -> None:
    catalog = dict(profile_module.profile_catalog())
    payload = {
        "schema_version": 3,
        "corpus_version": str(config.get("corpus_version") or DEFAULT_CORPUS_VERSION),
        "collection_mode": "external_service",
        "recommended_build_command": (
            f"python -m src.process.main build_bbk --logs-dir {corpus_dir} "
            f"--window-seconds {int(config.get('window_seconds') or DEFAULT_BBK_TRAIN_WINDOW_SECONDS)} "
            f"--time-bin-seconds {int(config.get('time_bin_seconds') or DEFAULT_TIME_BIN_SECONDS)}"
        ),
        "window_seconds": int(config.get("window_seconds") or DEFAULT_BBK_TRAIN_WINDOW_SECONDS),
        "time_bin_seconds": int(config.get("time_bin_seconds") or DEFAULT_TIME_BIN_SECONDS),
        "target": dict(config.get("target") or {}),
        "dataset_split_semantics": {
            "train": "Use for BBK/GMAE training only.",
            "calibration": "Use for threshold or score calibration only.",
            "holdout": "Use only for final benign FPR/false-alarms-per-hour reporting.",
        },
        "container_roles": dict(config.get("container_roles") or {}),
        "trace_scope": dict(config.get("trace_scope") or {}),
        "driver_roles": list(config.get("driver_roles") or []),
        "profiles": [
            {"profile_id": profile_id, **dict(meta or {})}
            for profile_id, meta in sorted(catalog.items())
        ],
        "expected_distribution": distribution,
        "runs": [
            {
                "run_id": str(run_meta.get("run_id") or ""),
                "split_role": str(run_meta.get("split_role") or ""),
                "duration_seconds": int(run_meta.get("duration_seconds") or 0),
                "trace_out": str(run_meta.get("trace_out") or ""),
                "driver_log": str(run_meta.get("driver_log") or ""),
                "driver_metrics": str(run_meta.get("driver_metrics") or ""),
                "split_semantics": str(run_meta.get("split_semantics") or ""),
                "target_container": dict(run_meta.get("target_container") or {}),
                "supporting_containers": list(run_meta.get("supporting_containers") or []),
                "driver_host": dict(run_meta.get("driver_host") or {}),
                "trace_scope": dict(run_meta.get("trace_scope") or {}),
                "driver_roles": list(run_meta.get("driver_roles") or []),
                "phases": list(run_meta.get("phases") or []),
                "phase_role_schedule": list(run_meta.get("phase_role_schedule") or []),
            }
            for run_meta in run_metas
        ],
    }
    write_json(str(corpus_dir / "corpus_manifest.json"), payload)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    ap.add_argument("--profile-module", default="")
    ap.add_argument("--corpus-dir", default="")
    ap.add_argument("--run-ids", default="")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    config = read_json(str(args.config))
    if not isinstance(config, dict):
        raise ValueError(f"invalid benign corpus config: {args.config}")

    profile_module_name = str(args.profile_module or config.get("profile_module") or "").strip()
    if not profile_module_name:
        raise ValueError("profile module is required via --profile-module or config.profile_module")
    profile_module = load_profile_module(profile_module_name)

    distribution = expected_distribution(config)
    errors = validate_distribution(distribution)
    errors.extend(validate_profile_catalog(config, profile_module))
    if args.dry_run:
        print(json.dumps({"distribution": distribution, "validation_errors": errors}, indent=2, sort_keys=True))
        if errors:
            raise SystemExit(2)
        return
    if errors:
        raise RuntimeError("; ".join(errors))

    corpus_dir = Path(str(args.corpus_dir or config.get("corpus_dir") or DEFAULT_BENIGN_CORPUS_DIR))
    corpus_dir.mkdir(parents=True, exist_ok=True)
    requested_run_ids = {
        item.strip()
        for item in str(args.run_ids or "").split(",")
        if item.strip()
    }

    run_metas: list[dict[str, Any]] = []
    for idx, run in enumerate(list(config.get("runs") or [])):
        run_id = str(run.get("run_id") or "")
        if requested_run_ids and run_id not in requested_run_ids:
            continue
        print(f"[benign-corpus] collecting run={run_id} split={run.get('split_role', 'train')}")
        run_metas.append(
            collect_run(
                config=config,
                profile_module=profile_module,
                corpus_dir=corpus_dir,
                run=run,
                base_seed=int(args.seed) + idx * 1000,
            )
        )

    write_corpus_manifest(
        corpus_dir=corpus_dir,
        config=config,
        profile_module=profile_module,
        run_metas=run_metas,
        distribution=distribution,
    )
    print(f"[benign-corpus] collected_runs={len(run_metas)} corpus_dir={corpus_dir}")


if __name__ == "__main__":
    main()
