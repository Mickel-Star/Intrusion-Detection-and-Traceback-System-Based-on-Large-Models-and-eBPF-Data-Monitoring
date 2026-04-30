#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scripts.eval_mix_accuracy import evaluate_benchmark_root, evaluate_single_run
from src.analysis.report_generator import AnalysisEngine
from src.common.benchmarking import (
    DEFAULT_THRESHOLD,
    load_scenario_manifest,
    role_label,
    sanitize_name,
    short_container_id,
)
from src.common.io import write_json
from src.process.log_parser import TraceeLogParser
from src.process.streaming_reduction import StreamingReductionConfig, StreamingReducer
from src.process.window_io import dump_window_graph


COMPOSE_FILE = ROOT_DIR / "deploy" / "docker-compose.yml"
BENCHMARK_ROOT = ROOT_DIR / "data" / "benchmarks_v3"
DRIVER_IMAGE = "curlimages/curl:8.6.0"
TRACEE_IMAGE = "aquasec/tracee:latest"
BASE_SERVICES = ["vuln-app", "vuln-app-dsock", "c2-listener"]
BASE_CONTAINERS = {
    "target": "drsec-target",
    "target_dsock": "drsec-target-dsock",
    "c2": "drsec-c2",
}
TRACEE_SCOPES = ["container", "comm!=tracee"]
TRACEE_EVENTS = [
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


def compose_cmd(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run_cmd(["docker", "compose", "-f", str(COMPOSE_FILE), *args], check=check)


def cleanup_runtime() -> None:
    for name in run_cmd(
        ["docker", "ps", "-aq", "--filter", "name=drsec-tracee-benchmark-", "--filter", "name=drsec-bench-"],
        capture=True,
        check=False,
    ).stdout.splitlines():
        item = name.strip()
        if item:
            run_cmd(["docker", "rm", "-f", item], capture=True, check=False)
    compose_cmd("--profile", "attack", "down", "-v", "--remove-orphans", check=False)


def get_container_id(container_name: str) -> str:
    result = run_cmd(["docker", "inspect", "-f", "{{.Id}}", container_name], capture=True, check=False)
    return result.stdout.strip().lower()


def get_container_network(container_name: str) -> str:
    result = run_cmd(
        ["docker", "inspect", "-f", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}", container_name],
        capture=True,
        check=True,
    )
    network_name = result.stdout.strip()
    if not network_name:
        raise RuntimeError(f"failed to resolve docker network for {container_name}")
    return network_name


def wait_for_service(network_name: str, service_name: str, timeout_seconds: int = 45) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        result = run_cmd(
            ["docker", "run", "--rm", "--network", network_name, DRIVER_IMAGE, "-fsS", f"http://{service_name}:5000/health"],
            capture=True,
            check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError(f"service did not become healthy: {service_name}")


def materialize_windows(trace_path: Path, windows_dir: Path, window_seconds: int, time_bin_seconds: int) -> int:
    parser = TraceeLogParser()
    reducer = StreamingReducer(
        config=StreamingReductionConfig(
            window_seconds=int(window_seconds),
            time_bin_seconds=int(time_bin_seconds),
        )
    )
    logs = parser.parse_log_file(str(trace_path))
    windows_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for graph, _metas in reducer.ingest_logs(logs):
        count += 1
        dump_window_graph(str(windows_dir / f"window_{count:04d}.json"), graph)
    return count


def _select_scenarios(manifest: Dict[str, Any], mode: str, scenario_ids: str, benchmark_split: str) -> List[Dict[str, Any]]:
    scenarios = list(manifest.get("scenarios", []) or [])
    if scenario_ids:
        requested = {item.strip() for item in scenario_ids.split(",") if item.strip()}
        scenarios = [scenario for scenario in scenarios if scenario.get("id") in requested]
    if benchmark_split:
        scenarios = [scenario for scenario in scenarios if str(scenario.get("benchmark_split") or "") == benchmark_split]
    return scenarios


def _repeat_ids(mode: str) -> List[int]:
    if mode == "full":
        return [1, 2, 3]
    return [1]


def _window_overlap_count(start_seconds: float, end_seconds: float, window_seconds: int, total_seconds: int) -> int:
    if end_seconds <= start_seconds:
        return 0
    window = max(int(window_seconds), 1)
    total_windows = max((int(total_seconds) + window - 1) // window, 1)
    count = 0
    for idx in range(total_windows):
        window_start = float(idx * window)
        window_end = float((idx + 1) * window)
        if window_start < float(end_seconds) and window_end > float(start_seconds):
            count += 1
    return count


def _command_variants(scenario: Dict[str, Any]) -> List[Dict[str, Any]]:
    variants: List[Dict[str, Any]] = []
    for idx, raw in enumerate(list(scenario.get("command_variants") or []), start=1):
        if isinstance(raw, dict):
            command = str(raw.get("command") or raw.get("attack_command") or "").strip()
            if not command:
                continue
            variant_id = str(raw.get("variant_id") or raw.get("id") or f"variant_{idx:02d}").strip()
            variants.append(
                {
                    "variant_id": variant_id,
                    "command_template_id": str(raw.get("command_template_id") or f"{scenario.get('id')}.{variant_id}").strip(),
                    "parameters": dict(raw.get("parameters") or {}) if isinstance(raw.get("parameters"), dict) else {},
                    "command": command,
                    "description": str(raw.get("description") or "").strip(),
                    "index": int(idx),
                }
            )
        else:
            command = str(raw or "").strip()
            if command:
                variants.append(
                    {
                        "variant_id": f"variant_{idx:02d}",
                        "command_template_id": f"{scenario.get('id')}.inline_{idx:02d}",
                        "parameters": {},
                        "command": command,
                        "description": "",
                        "index": int(idx),
                    }
                )
    return variants


def _select_command_variant(scenario: Dict[str, Any], repeat_id: int) -> Dict[str, Any]:
    variants = _command_variants(scenario)
    if variants:
        return dict(variants[(int(repeat_id) - 1) % len(variants)])
    command = str(scenario.get("attack_command") or scenario.get("command") or "").strip()
    return {
        "variant_id": f"repeat_{int(repeat_id):02d}",
        "command_template_id": f"{scenario.get('id')}.fallback",
        "parameters": {},
        "command": command,
        "description": "fallback command",
        "index": int(repeat_id),
    }


def benchmark_plan_summary(
    scenarios: List[Dict[str, Any]],
    *,
    mode: str,
    window_seconds: int,
    time_bin_seconds: int,
) -> Dict[str, Any]:
    repeats = _repeat_ids(mode)
    by_family: Dict[str, Dict[str, Any]] = {}
    by_split: Dict[str, int] = {}
    runs: List[Dict[str, Any]] = []

    for scenario in scenarios:
        family_id = str(scenario.get("family_id") or scenario.get("id") or "")
        split = str(scenario.get("benchmark_split") or "")
        variants = _command_variants(scenario)
        warmup_seconds, attack_seconds, cooldown_seconds = _scenario_stage_seconds(scenario)
        total_seconds = int(scenario.get("duration_seconds") or (warmup_seconds + attack_seconds + cooldown_seconds))
        attack_stage_windows = _window_overlap_count(
            float(warmup_seconds),
            float(warmup_seconds + attack_seconds),
            int(window_seconds),
            total_seconds,
        )
        expected_windows = max((total_seconds + int(window_seconds) - 1) // int(window_seconds), 1)

        family = by_family.setdefault(
            family_id,
            {
                "family_id": family_id,
                "benchmark_split": split,
                "scenario_ids": [],
                "run_count": 0,
                "expected_window_count": 0,
                "attack_stage_window_count_sum": 0,
                "attack_stage_window_count_avg": 0.0,
                "command_variant_count": 0,
            },
        )
        family["scenario_ids"].append(str(scenario.get("id") or ""))
        family["run_count"] = int(family["run_count"]) + len(repeats)
        family["expected_window_count"] = int(family["expected_window_count"]) + expected_windows * len(repeats)
        family["attack_stage_window_count_sum"] = int(family["attack_stage_window_count_sum"]) + attack_stage_windows * len(repeats)
        family["command_variant_count"] = max(
            int(family["command_variant_count"]),
            len(variants),
        )
        by_split[split] = int(by_split.get(split, 0)) + len(repeats)

        for repeat_id in repeats:
            selected_variant = _select_command_variant(scenario, repeat_id)
            runs.append(
                {
                    "scenario_id": str(scenario.get("id") or ""),
                    "family_id": family_id,
                    "benchmark_split": split,
                    "repeat_id": int(repeat_id),
                    "variant_id": str(selected_variant.get("variant_id") or ""),
                    "command_template_id": str(selected_variant.get("command_template_id") or ""),
                    "parameters": dict(selected_variant.get("parameters") or {}),
                    "duration_seconds": int(total_seconds),
                    "warmup_seconds": int(warmup_seconds),
                    "attack_seconds": int(attack_seconds),
                    "cooldown_seconds": int(cooldown_seconds),
                    "expected_windows": int(expected_windows),
                    "expected_attack_stage_windows": int(attack_stage_windows),
                    "selected_attack_command_index": int(selected_variant.get("index") or 0),
                }
            )

    for family in by_family.values():
        run_count = int(family.get("run_count") or 0)
        family["scenario_ids"] = sorted(set(str(item) for item in family.get("scenario_ids") or []))
        family["attack_stage_window_count_avg"] = (
            float(family.get("attack_stage_window_count_sum") or 0) / float(run_count)
            if run_count > 0
            else 0.0
        )

    return {
        "schema_version": 1,
        "mode": str(mode),
        "window_seconds": int(window_seconds),
        "time_bin_seconds": int(time_bin_seconds),
        "scenario_count": int(len(scenarios)),
        "repeat_ids": repeats,
        "run_count": int(len(runs)),
        "expected_window_count": int(sum(int(item.get("expected_windows") or 0) for item in runs)),
        "expected_attack_stage_window_count": int(sum(int(item.get("expected_attack_stage_windows") or 0) for item in runs)),
        "by_split_run_count": dict(sorted(by_split.items())),
        "by_family": dict(sorted(by_family.items())),
        "runs": runs,
    }


def validate_benchmark_plan(scenarios: List[Dict[str, Any]], *, mode: str) -> List[str]:
    errors: List[str] = []
    repeats = _repeat_ids(mode)
    for scenario in scenarios:
        scenario_id = str(scenario.get("id") or "")
        warmup_seconds, attack_seconds, cooldown_seconds = _scenario_stage_seconds(scenario)
        duration_seconds = int(scenario.get("duration_seconds") or 0)
        if warmup_seconds <= 0 or attack_seconds <= 0 or cooldown_seconds <= 0:
            errors.append(f"{scenario_id}: mixed run must define positive warmup/attack/cooldown seconds")
        if duration_seconds != int(warmup_seconds + attack_seconds + cooldown_seconds):
            errors.append(
                f"{scenario_id}: duration_seconds={duration_seconds} does not equal "
                f"warmup+attack+cooldown={warmup_seconds + attack_seconds + cooldown_seconds}"
            )
        variants = _command_variants(scenario)
        if len(variants) < len(repeats):
            errors.append(
                f"{scenario_id}: command_variants={len(variants)} is below repeat_count={len(repeats)}"
            )
        commands = [str(item.get("command") or "") for item in variants]
        variant_ids = [str(item.get("variant_id") or "") for item in variants]
        if len(set(commands)) != len(commands):
            errors.append(f"{scenario_id}: command_variants contains duplicate commands")
        if len(set(variant_ids)) != len(variant_ids):
            errors.append(f"{scenario_id}: command_variants contains duplicate variant_id")
    return errors


def _scenario_run_dir(scenario_id: str, repeat_id: int) -> Path:
    return BENCHMARK_ROOT / scenario_id / f"repeat_{repeat_id:02d}"


def _make_labels_payload(
    scenario: Dict[str, Any],
    driver_container_name: str,
    driver_container_id: str,
    base_container_ids: Dict[str, str],
) -> Dict[str, Any]:
    containers = []
    driver_role = str(scenario.get("driver_role") or "")
    if driver_container_id:
        containers.append(
            {
                "role": driver_role,
                "container_id": driver_container_id,
                "container_name": driver_container_name,
                "label": role_label(driver_role, scenario.get("positive_roles") or [], scenario.get("negative_roles") or []),
            }
        )
    for role_name, container_name in BASE_CONTAINERS.items():
        container_id = base_container_ids.get(role_name) or ""
        if not container_id:
            continue
        containers.append(
            {
                "role": role_name,
                "container_id": container_id,
                "container_name": container_name,
                "label": role_label(role_name, scenario.get("positive_roles") or [], scenario.get("negative_roles") or []),
            }
        )
    return {
        "schema_version": 1,
        "scenario_id": scenario.get("id"),
        "kind": scenario.get("kind"),
        "positive_roles": scenario.get("positive_roles") or [],
        "negative_roles": scenario.get("negative_roles") or [],
        "containers": containers,
    }


def _build_run_meta(
    scenario: Dict[str, Any],
    repeat_id: int,
    selected_variant: Dict[str, Any],
    trace_path: Path,
    driver_container_name: str,
    driver_container_id: str,
    base_container_ids: Dict[str, str],
    windows_dir: Path,
    metrics_path: Path,
    window_seconds: int,
    time_bin_seconds: int,
    stage_boundaries: Dict[str, float],
) -> Dict[str, Any]:
    target_service = str(scenario.get("target_service") or "")
    target_role = "target_dsock" if target_service == "vuln-app-dsock" else "target"
    target_container_name = BASE_CONTAINERS.get(target_role, "")
    supporting_containers = []
    for role_name, container_name in BASE_CONTAINERS.items():
        if role_name == target_role:
            continue
        supporting_containers.append(
            {
                "role": role_name,
                "service": "c2-listener" if role_name == "c2" else role_name,
                "container_name": container_name,
                "container_id": base_container_ids.get(role_name) or "",
            }
        )
    split = str(scenario.get("benchmark_split") or "")
    split_semantics = {
        "attack_dev": "Pipeline debugging and qualitative case-study split only; do not use for GMAE training or threshold calibration.",
        "attack_holdout": "Final held-out attack benchmark split; do not use for threshold selection.",
    }
    return {
        "scenario_id": str(scenario.get("id") or ""),
        "kind": str(scenario.get("kind") or ""),
        "family_id": str(scenario.get("family_id") or scenario.get("id") or ""),
        "benchmark_split": split,
        "benchmark_split_semantics": split_semantics.get(split, ""),
        "repeat_id": int(repeat_id),
        "variant_id": str(selected_variant.get("variant_id") or ""),
        "command_template_id": str(selected_variant.get("command_template_id") or ""),
        "parameters": dict(selected_variant.get("parameters") or {}),
        "driver_role": str(scenario.get("driver_role") or ""),
        "driver_container": {
            "role": str(scenario.get("driver_role") or ""),
            "container_name": driver_container_name,
            "container_id": driver_container_id,
        },
        "driver_container_name": driver_container_name,
        "driver_container_id": driver_container_id,
        "target_service": target_service,
        "target_container": {
            "role": target_role,
            "service": target_service,
            "container_name": target_container_name,
            "container_id": base_container_ids.get(target_role) or "",
        },
        "supporting_containers": supporting_containers,
        "trace_scope": {
            "scope_expression": list(TRACEE_SCOPES),
            "events": list(TRACEE_EVENTS),
            "target_role": target_role,
            "supporting_roles": [str(item.get("role") or "") for item in supporting_containers],
            "driver_role": str(scenario.get("driver_role") or ""),
        },
        "target_container_id": base_container_ids.get("target") or "",
        "target_dsock_container_id": base_container_ids.get("target_dsock") or "",
        "c2_container_id": base_container_ids.get("c2") or "",
        "trace_out": str(trace_path),
        "windows_dir": str(windows_dir),
        "metrics_path": str(metrics_path),
        "window_seconds": int(window_seconds),
        "time_bin_seconds": int(time_bin_seconds),
        "stage_boundaries": dict(stage_boundaries or {}),
        "threshold": float(DEFAULT_THRESHOLD),
        "max_windows": 0,
        "command": str(scenario.get("command") or ""),
        "attack_command": str(scenario.get("attack_command") or scenario.get("command") or ""),
        "selected_attack_command": str(selected_variant.get("command") or ""),
        "warmup_command": str(scenario.get("warmup_command") or ""),
        "cooldown_command": str(scenario.get("cooldown_command") or ""),
        "duration_seconds": int(scenario.get("duration_seconds") or 0),
        "warmup_seconds": int(scenario.get("warmup_seconds") or 0),
        "attack_seconds": int(scenario.get("attack_seconds") or 0),
        "cooldown_seconds": int(scenario.get("cooldown_seconds") or 0),
    }


def _default_benign_stage_command(service_name: str, duration_seconds: int) -> str:
    loops = max(int(duration_seconds) // 2, 1)
    return (
        "for i in $(seq 1 %d); do "
        "TOKEN=$(curl -s -H 'Content-Type: application/json' "
        "-d '{\"username\":\"alice\",\"password\":\"password\"}' "
        "'http://%s:5000/api/login' | sed -n 's/.*\"token\":\"\\([^\"]*\\)\".*/\\1/p'); "
        "curl -s 'http://%s:5000/health' >/dev/null; "
        "curl -s 'http://%s:5000/api/items' >/dev/null; "
        "curl -s 'http://%s:5000/api/search?q=sku' >/dev/null; "
        "curl -s -H 'Content-Type: application/json' "
        "-d '{\"customer\":\"alice\",\"item\":\"sku-001\",\"quantity\":1}' "
        "'http://%s:5000/api/order' >/dev/null; "
        "if [ -n \"$TOKEN\" ]; then "
        "curl -s -H \"Authorization: Bearer $TOKEN\" 'http://%s:5000/api/me' >/dev/null; "
        "curl -s -X POST -H \"Authorization: Bearer $TOKEN\" 'http://%s:5000/api/logout' >/dev/null; "
        "fi; sleep 2; done"
    ) % (loops, service_name, service_name, service_name, service_name, service_name, service_name, service_name)


def _scenario_stage_seconds(scenario: Dict[str, Any]) -> tuple[int, int, int]:
    warmup_seconds = int(scenario.get("warmup_seconds") or 0)
    attack_seconds = int(scenario.get("attack_seconds") or 0)
    cooldown_seconds = int(scenario.get("cooldown_seconds") or 0)
    if warmup_seconds or attack_seconds or cooldown_seconds:
        return warmup_seconds, attack_seconds, cooldown_seconds
    duration_seconds = int(scenario.get("duration_seconds") or 0)
    return 0, duration_seconds, 0


def _select_attack_command(scenario: Dict[str, Any], repeat_id: int) -> str:
    return str(_select_command_variant(scenario, repeat_id).get("command") or "").strip()


def _timed_stage(command: str, duration_seconds: int) -> str:
    duration = max(int(duration_seconds), 0)
    if duration <= 0:
        return str(command)
    return (
        "_stage_start=$(date +%s); "
        "{ " + str(command) + "; }; "
        "_stage_elapsed=$(($(date +%s)-$_stage_start)); "
        f"_stage_remaining=$(({duration}-$_stage_elapsed)); "
        "if [ $_stage_remaining -gt 0 ]; then sleep $_stage_remaining; fi"
    )


def _build_stage_command(
    scenario: Dict[str, Any],
    repeat_id: int,
    selected_variant: Dict[str, Any] | None = None,
) -> str:
    service_name = str(scenario.get("target_service") or "vuln-app")
    warmup_seconds, attack_seconds, cooldown_seconds = _scenario_stage_seconds(scenario)
    warmup_command = str(scenario.get("warmup_command") or "").strip()
    variant = selected_variant or _select_command_variant(scenario, repeat_id)
    attack_command = str(variant.get("command") or "").strip()
    cooldown_command = str(scenario.get("cooldown_command") or "").strip()
    if warmup_seconds > 0 and not warmup_command:
        warmup_command = _default_benign_stage_command(service_name, warmup_seconds)
    if cooldown_seconds > 0 and not cooldown_command:
        cooldown_command = _default_benign_stage_command(service_name, cooldown_seconds)
    parts = ["set -eu"]
    if warmup_command:
        parts.append(_timed_stage(warmup_command, warmup_seconds))
    if attack_command:
        parts.append(_timed_stage(attack_command, attack_seconds))
    if cooldown_command:
        parts.append(_timed_stage(cooldown_command, cooldown_seconds))
    parts.append("sleep 2")
    return "; ".join(parts)


def _build_stage_boundaries(scenario: Dict[str, Any], tracee_settle_seconds: int) -> Dict[str, float]:
    warmup_seconds, attack_seconds, cooldown_seconds = _scenario_stage_seconds(scenario)
    cursor = float(tracee_settle_seconds)
    warmup_start = cursor
    warmup_end = warmup_start + float(warmup_seconds)
    attack_start = warmup_end
    attack_end = attack_start + float(attack_seconds)
    cooldown_start = attack_end
    cooldown_end = cooldown_start + float(cooldown_seconds)
    return {
        "warmup_start": float(warmup_start),
        "warmup_end": float(warmup_end),
        "attack_start": float(attack_start),
        "attack_end": float(attack_end),
        "cooldown_start": float(cooldown_start),
        "cooldown_end": float(cooldown_end),
    }


def execute_run(
    scenario: Dict[str, Any],
    repeat_id: int,
    window_seconds: int,
    time_bin_seconds: int,
    engine: AnalysisEngine,
) -> Dict[str, Any]:
    run_dir = _scenario_run_dir(str(scenario.get("id") or "unknown"), repeat_id)
    if run_dir.exists():
        shutil.rmtree(run_dir)
    windows_dir = run_dir / "windows"
    debug_dir = run_dir / "debug"
    run_dir.mkdir(parents=True, exist_ok=True)
    debug_dir.mkdir(parents=True, exist_ok=True)

    trace_path = run_dir / "trace.log"
    labels_path = run_dir / "labels.json"
    run_meta_path = run_dir / "run_meta.json"
    metrics_path = run_dir / "metrics.json"
    eval_debug_path = debug_dir / "eval_debug.json"
    driver_log_path = debug_dir / "driver.log"

    cleanup_runtime()
    compose_cmd("--profile", "attack", "up", "-d", *BASE_SERVICES)

    network_name = get_container_network(BASE_CONTAINERS["target"])
    wait_for_service(network_name, "vuln-app")
    wait_for_service(network_name, "vuln-app-dsock")

    base_container_ids = {
        role_name: get_container_id(container_name)
        for role_name, container_name in BASE_CONTAINERS.items()
    }

    tracee_name = f"drsec-tracee-benchmark-{sanitize_name(scenario.get('id'))}-r{repeat_id:02d}"
    trace_fp = trace_path.open("w", encoding="utf-8")
    tracee_proc = subprocess.Popen(
        [
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
            TRACEE_IMAGE,
            "--containers",
            "enrich=true",
            "--containers",
            "sockets.docker=/var/run/docker.sock",
            "--containers",
            "cgroupfs.path=/sys/fs/cgroup",
            "--containers",
            "cgroupfs.force=true",
            "--scope",
            TRACEE_SCOPES[0],
            "--scope",
            TRACEE_SCOPES[1],
            "--events",
            ",".join(TRACEE_EVENTS),
            "--output",
            "table",
            "--output",
            "option:parse-arguments",
        ],
        cwd=str(ROOT_DIR),
        stdout=trace_fp,
        stderr=subprocess.STDOUT,
        text=True,
    )

    driver_container_name = f"drsec-bench-{sanitize_name(scenario.get('id'))}-r{repeat_id:02d}-{scenario.get('driver_role')}"
    driver_id = ""
    tracee_settle_seconds = 3
    stage_boundaries = _build_stage_boundaries(scenario, tracee_settle_seconds)
    selected_variant = _select_command_variant(scenario, repeat_id)
    selected_attack_command = str(selected_variant.get("command") or "")
    driver_command = _build_stage_command(scenario, repeat_id, selected_variant=selected_variant)
    try:
        time.sleep(tracee_settle_seconds)
        run_cmd(["docker", "rm", "-f", driver_container_name], capture=True, check=False)
        driver_id = run_cmd(
            [
                "docker",
                "run",
                "-d",
                "--name",
                driver_container_name,
                "--network",
                network_name,
                DRIVER_IMAGE,
                "sh",
                "-lc",
                driver_command,
            ],
            capture=True,
            check=True,
        ).stdout.strip().lower()

        wait_timeout = int(scenario.get("duration_seconds") or 0) + int(tracee_settle_seconds) + 60
        wait_result = run_cmd(["docker", "wait", driver_container_name], capture=True, check=True, timeout=wait_timeout)
        driver_logs = run_cmd(["docker", "logs", driver_container_name], capture=True, check=False).stdout
        driver_log_path.write_text(driver_logs, encoding="utf-8")
        exit_status = int((wait_result.stdout or "0").strip() or 0)
        if exit_status != 0:
            raise RuntimeError(f"driver container exited with status {exit_status}: {driver_container_name}")
        time.sleep(3)
    finally:
        run_cmd(["docker", "rm", "-f", tracee_name], capture=True, check=False)
        try:
            tracee_proc.wait(timeout=20)
        except Exception:
            tracee_proc.kill()
        trace_fp.close()

    labels_payload = _make_labels_payload(scenario, driver_container_name, driver_id, base_container_ids)
    write_json(str(labels_path), labels_payload)

    run_meta = _build_run_meta(
        scenario,
        repeat_id,
        selected_variant,
        trace_path,
        driver_container_name,
        driver_id,
        base_container_ids,
        windows_dir,
        metrics_path,
        window_seconds,
        time_bin_seconds,
        stage_boundaries,
    )
    run_meta["executed_command"] = driver_command
    run_meta["selected_attack_command"] = selected_attack_command
    write_json(str(run_meta_path), run_meta)

    window_count = materialize_windows(trace_path, windows_dir, window_seconds, time_bin_seconds)
    summary = evaluate_single_run(
        windows_dir,
        labels_path=labels_path,
        run_meta_path=run_meta_path,
        threshold=DEFAULT_THRESHOLD,
        engine=engine,
        include_debug=True,
    )
    debug_payload = summary.pop("debug", {})
    summary["window_count"] = int(window_count)
    write_json(str(metrics_path), summary)
    write_json(str(eval_debug_path), debug_payload)

    cleanup_runtime()
    return {
        "scenario_id": str(scenario.get("id") or ""),
        "family_id": str(scenario.get("family_id") or scenario.get("id") or ""),
        "repeat_id": int(repeat_id),
        "variant_id": str(selected_variant.get("variant_id") or ""),
        "command_template_id": str(selected_variant.get("command_template_id") or ""),
        "parameters": dict(selected_variant.get("parameters") or {}),
        "run_dir": str(run_dir),
        "window_count": int(window_count),
        "window_support": int(((summary.get("window_level") or {}).get("support")) or 0),
        "metrics_path": str(metrics_path),
    }


def main() -> None:
    global BENCHMARK_ROOT

    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["smoke", "full"], default="full")
    ap.add_argument("--scenario-set", default="default")
    ap.add_argument("--scenario-ids", default="")
    ap.add_argument("--benchmark-split", choices=["", "attack_dev", "attack_holdout"], default="")
    ap.add_argument("--benchmark-root", default=str(BENCHMARK_ROOT))
    ap.add_argument("--window-seconds", type=int, default=30)
    ap.add_argument("--time-bin-seconds", type=int, default=2)
    ap.add_argument("--threshold-sweep", action="store_true", default=False)
    ap.add_argument("--dry-run", action="store_true", default=False, help="validate and print the benchmark plan without Docker/Tracee")
    ap.add_argument("--dry-run-output", default="", help="optional JSON path for --dry-run plan output")
    args = ap.parse_args()

    BENCHMARK_ROOT = Path(str(args.benchmark_root)).resolve()

    manifest = load_scenario_manifest(str(ROOT_DIR), args.scenario_set)
    scenarios = _select_scenarios(manifest, args.mode, args.scenario_ids, args.benchmark_split)
    if not scenarios:
        raise ValueError("no scenarios selected")

    if bool(args.dry_run):
        plan = benchmark_plan_summary(
            scenarios,
            mode=str(args.mode),
            window_seconds=int(args.window_seconds),
            time_bin_seconds=int(args.time_bin_seconds),
        )
        errors = validate_benchmark_plan(scenarios, mode=str(args.mode))
        plan["validation_errors"] = errors
        print(json.dumps(plan, indent=2, sort_keys=True))
        if args.dry_run_output:
            write_json(str(args.dry_run_output), plan)
        if errors:
            raise SystemExit(2)
        return

    BENCHMARK_ROOT.mkdir(parents=True, exist_ok=True)
    engine = AnalysisEngine()
    executed_runs: List[Dict[str, Any]] = []

    try:
        for scenario in scenarios:
            for repeat_id in _repeat_ids(args.mode):
                print(f"[benchmark] scenario={scenario['id']} repeat={repeat_id} kind={scenario['kind']}")
                executed_runs.append(
                    execute_run(
                        scenario,
                        repeat_id,
                        int(args.window_seconds),
                        int(args.time_bin_seconds),
                        engine,
                    )
                )
    finally:
        cleanup_runtime()

    summary = evaluate_benchmark_root(
        BENCHMARK_ROOT,
        threshold=DEFAULT_THRESHOLD,
        threshold_sweep=bool(args.threshold_sweep),
        engine=engine,
        run_id_filter={str(Path(item["run_dir"]).relative_to(BENCHMARK_ROOT)) for item in executed_runs},
    )

    summary_path = BENCHMARK_ROOT / f"summary_{sanitize_name(args.scenario_set)}_{args.mode}.json"
    write_json(str(summary_path), summary)

    run_index = {
        "scenario_set": args.scenario_set,
        "mode": args.mode,
        "benchmark_split": args.benchmark_split,
        "window_seconds": int(args.window_seconds),
        "time_bin_seconds": int(args.time_bin_seconds),
        "threshold_sweep": bool(args.threshold_sweep),
        "manifest_path": manifest.get("manifest_path"),
        "executed_runs": executed_runs,
        "summary_path": str(summary_path),
    }
    write_json(str(BENCHMARK_ROOT / f"run_index_{sanitize_name(args.scenario_set)}_{args.mode}.json"), run_index)

    if args.threshold_sweep:
        tuned = summary.get("tuned_threshold") or {}
        recommended = {
            "scenario_set": args.scenario_set,
            "mode": args.mode,
            "metric": "scenario_level_recall_then_window_recall_debug_only",
            "recommended_threshold": float(tuned.get("threshold", DEFAULT_THRESHOLD)),
            "selected_on": "validation_repeat_1_debug_only",
            "do_not_use_for_formal_calibration": True,
            "calibration_note": (
                "Formal threshold calibration must use the benign calibration split. "
                "attack_dev is for pipeline debugging and case studies only."
            ),
            "summary_path": str(summary_path),
        }
        write_json(str(BENCHMARK_ROOT / f"recommended_threshold_{sanitize_name(args.scenario_set)}_{args.mode}.json"), recommended)

    fixed_threshold = summary.get("fixed_threshold") or {}
    tuned_threshold = summary.get("tuned_threshold") or {}
    if fixed_threshold and tuned_threshold:
        print(
            "[benchmark] fixed_threshold=%.2f fixed_scenario_recall=%.4f tuned_threshold=%.2f tuned_scenario_recall=%.4f"
            % (
                float(fixed_threshold.get("threshold", DEFAULT_THRESHOLD)),
                float(((fixed_threshold.get("test") or {}).get("scenario_level_recall")) or 0.0),
                float(tuned_threshold.get("threshold", DEFAULT_THRESHOLD)),
                float(((tuned_threshold.get("test") or {}).get("scenario_level_recall")) or 0.0),
            )
        )
    else:
        print(
            "[benchmark] scenario_recall=%.4f window_recall=%.4f"
            % (
                float(summary.get("scenario_level_recall") or 0.0),
                float(summary.get("window_level_recall") or 0.0),
            )
        )


if __name__ == "__main__":
    main()
