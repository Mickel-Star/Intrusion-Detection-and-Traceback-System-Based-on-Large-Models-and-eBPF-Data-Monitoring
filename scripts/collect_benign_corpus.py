#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import json
import math
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Sequence

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.common.defaults import DEFAULT_BENIGN_CORPUS_DIR
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


def normalize_phases(run: dict[str, Any]) -> list[dict[str, Any]]:
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
            }
        )
        start_offset = end_offset
    return phases


def expected_distribution(config: dict[str, Any]) -> dict[str, Any]:
    window_seconds = int(config.get("window_seconds") or 15)
    run_summaries = []
    profile_windows: dict[str, int] = {}
    role_windows: dict[str, int] = {}
    train_profile_windows: dict[str, int] = {}
    for run in list(config.get("runs") or []):
        phases = normalize_phases(run)
        role = str(run.get("split_role") or "train")
        run_windows = 0
        for phase in phases:
            windows = int(math.floor(float(phase["duration_seconds"]) / float(window_seconds)))
            run_windows += windows
            profile_id = str(phase["profile_id"])
            profile_windows[profile_id] = int(profile_windows.get(profile_id, 0)) + windows
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
        "total_expected_windows": int(sum(role_windows.values())),
        "role_expected_windows": dict(sorted(role_windows.items())),
        "profile_expected_windows": dict(sorted(profile_windows.items())),
        "train_profile_expected_windows": dict(sorted(train_profile_windows.items())),
        "train_profile_imbalance": profile_imbalance,
        "runs": run_summaries,
    }


def validate_distribution(summary: dict[str, Any]) -> list[str]:
    errors = []
    role_windows = dict(summary.get("role_expected_windows") or {})
    profile_windows = dict(summary.get("profile_expected_windows") or {})
    train_imbalance = dict(summary.get("train_profile_imbalance") or {})
    if int(role_windows.get("train", 0)) < 200:
        errors.append("expected train windows below v2 target: < 200")
    if int(role_windows.get("calibration", 0)) < 50:
        errors.append("expected calibration windows below v2 target: < 50")
    if int(role_windows.get("holdout", 0)) < 80:
        errors.append("expected holdout windows below v2 target: < 80")
    for profile_id, count in sorted(profile_windows.items()):
        if int(count) < 50:
            errors.append(f"profile expected windows below v2 target: {profile_id}={count} < 50")
    for profile_id, ratio in sorted(train_imbalance.items()):
        if float(ratio) > 0.4:
            errors.append(f"train profile imbalance above 40%: {profile_id}={ratio:.3f}")
    return errors


def validate_profile_catalog(config: dict[str, Any], profile_module) -> list[str]:
    catalog = dict(profile_module.profile_catalog())
    known = set(str(key) for key in catalog)
    errors = []
    for run in list(config.get("runs") or []):
        for phase in normalize_phases(run):
            profile_id = str(phase["profile_id"])
            if profile_id not in known:
                errors.append(f"unknown profile_id in config: {profile_id}")
    prewarm_profile = str(config.get("prewarm_profile") or "")
    if prewarm_profile and prewarm_profile not in known:
        errors.append(f"unknown prewarm_profile in config: {prewarm_profile}")
    return errors


def run_phases(
    *,
    profile_module,
    phases: list[dict[str, Any]],
    base_url: str,
    seed: int,
    log_path: Path,
) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as fp:
        for idx, phase in enumerate(phases, start=1):
            profile_id = str(phase["profile_id"])
            duration = float(phase["duration_seconds"])
            phase_seed = int(seed) + idx
            fp.write(f"phase_start id={phase['phase_id']} profile={profile_id} duration={duration} seed={phase_seed}\n")
            fp.flush()
            profile_module.run_profile(
                profile_id,
                base_url=str(base_url),
                duration_seconds=duration,
                seed=phase_seed,
            )
            fp.write(f"phase_end id={phase['phase_id']} profile={profile_id}\n")
            fp.flush()


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
    phases = normalize_phases(run)
    run_dir = corpus_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    trace_path = run_dir / "trace.log"
    driver_log_path = run_dir / "driver.log"
    prewarm_log_path = run_dir / "prewarm.log"
    run_meta_path = run_dir / "run_meta.json"

    wait_for_health(health_url, timeout_seconds=int(target.get("health_timeout_seconds") or 60))
    prewarm_seconds = int(config.get("prewarm_seconds") or 0)
    prewarm_profile = str(config.get("prewarm_profile") or phases[0]["profile_id"])
    if prewarm_seconds > 0:
        run_phases(
            profile_module=profile_module,
            phases=[
                {
                    "phase_id": f"{run_id}_prewarm",
                    "profile_id": prewarm_profile,
                    "start_offset_seconds": 0.0,
                    "end_offset_seconds": float(prewarm_seconds),
                    "duration_seconds": int(prewarm_seconds),
                }
            ],
            base_url=base_url,
            seed=int(base_seed),
            log_path=prewarm_log_path,
        )

    tracee_name = f"drsec-tracee-benign-corpus-{run_id}"
    run_cmd(["docker", "rm", "-f", tracee_name], capture=True, check=False)
    tracee_proc, trace_fp = start_tracee(trace_path, tracee_name, config)
    try:
        time.sleep(float(config.get("tracee_settle_seconds") or 3.0))
        run_phases(
            profile_module=profile_module,
            phases=phases,
            base_url=base_url,
            seed=int(base_seed),
            log_path=driver_log_path,
        )
        time.sleep(float(config.get("tracee_flush_seconds") or 3.0))
    finally:
        stop_tracee(tracee_proc, tracee_name, trace_fp)

    payload = {
        "schema_version": 2,
        "corpus_version": str(config.get("corpus_version") or "v2"),
        "run_id": run_id,
        "kind": "benign_corpus_run",
        "split_role": str(run.get("split_role") or "train"),
        "target_service": str(target.get("name") or ""),
        "target_base_url": base_url,
        "trace_out": str(trace_path),
        "driver_log": str(driver_log_path),
        "prewarm_log": str(prewarm_log_path),
        "duration_seconds": int(sum(int(phase["duration_seconds"]) for phase in phases)),
        "prewarm_seconds": int(prewarm_seconds),
        "random_seed": int(base_seed),
        "training_pool": bool(run.get("training_pool", True)),
        "bootstrap_only": bool(run.get("bootstrap_only", False)),
        "window_seconds": int(config.get("window_seconds") or 15),
        "phases": phases,
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
        "schema_version": 2,
        "corpus_version": str(config.get("corpus_version") or "v2"),
        "collection_mode": "external_service",
        "recommended_build_command": (
            f"python -m src.process.main build_bbk --logs-dir {corpus_dir} "
            f"--window-seconds {int(config.get('window_seconds') or 15)}"
        ),
        "window_seconds": int(config.get("window_seconds") or 15),
        "target": dict(config.get("target") or {}),
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
                "phases": list(run_meta.get("phases") or []),
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
