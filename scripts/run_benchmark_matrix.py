#!/usr/bin/env python3
from __future__ import annotations

import argparse
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
from src.common.defaults import DEFAULT_WINDOW_SECONDS
from src.common.io import write_json
from src.process.log_parser import TraceeLogParser
from src.process.streaming_reduction import StreamingReductionConfig, StreamingReducer
from src.process.window_io import dump_window_graph


COMPOSE_FILE = ROOT_DIR / "deploy" / "docker-compose.yml"
BENCHMARK_ROOT = ROOT_DIR / "data" / "benchmarks"
DRIVER_IMAGE = "curlimages/curl:8.6.0"
TRACEE_IMAGE = "aquasec/tracee:latest"
BASE_SERVICES = ["vuln-app", "vuln-app-dsock", "c2-listener"]
BASE_CONTAINERS = {
    "target": "drsec-target",
    "target_dsock": "drsec-target-dsock",
    "c2": "drsec-c2",
}


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


def materialize_windows(trace_path: Path, windows_dir: Path, window_seconds: int) -> int:
    parser = TraceeLogParser()
    reducer = StreamingReducer(config=StreamingReductionConfig(window_seconds=int(window_seconds), time_bin_seconds=1))
    logs = parser.parse_log_file(str(trace_path))
    windows_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for graph, _metas in reducer.ingest_logs(logs):
        count += 1
        dump_window_graph(str(windows_dir / f"window_{count:04d}.json"), graph)
    return count


def _select_scenarios(manifest: Dict[str, Any], mode: str, scenario_ids: str) -> List[Dict[str, Any]]:
    scenarios = list(manifest.get("scenarios", []) or [])
    if scenario_ids:
        requested = {item.strip() for item in scenario_ids.split(",") if item.strip()}
        scenarios = [scenario for scenario in scenarios if scenario.get("id") in requested]
    return scenarios


def _repeat_ids(mode: str) -> List[int]:
    if mode == "full":
        return [1, 2, 3]
    return [1]


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
    trace_path: Path,
    driver_container_name: str,
    driver_container_id: str,
    base_container_ids: Dict[str, str],
    windows_dir: Path,
    metrics_path: Path,
    window_seconds: int,
) -> Dict[str, Any]:
    return {
        "scenario_id": str(scenario.get("id") or ""),
        "kind": str(scenario.get("kind") or ""),
        "repeat_id": int(repeat_id),
        "driver_role": str(scenario.get("driver_role") or ""),
        "driver_container_name": driver_container_name,
        "driver_container_id": driver_container_id,
        "target_container_id": base_container_ids.get("target") or "",
        "target_dsock_container_id": base_container_ids.get("target_dsock") or "",
        "c2_container_id": base_container_ids.get("c2") or "",
        "trace_out": str(trace_path),
        "windows_dir": str(windows_dir),
        "metrics_path": str(metrics_path),
        "window_seconds": int(window_seconds),
        "threshold": float(DEFAULT_THRESHOLD),
        "max_windows": 0,
        "command": str(scenario.get("command") or ""),
        "duration_seconds": int(scenario.get("duration_seconds") or 0),
    }


def execute_run(
    scenario: Dict[str, Any],
    repeat_id: int,
    window_seconds: int,
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
            "container",
            "--scope",
            "comm!=tracee",
            "--events",
            "sched_process_exec,execve,openat,read,write,close,connect,accept,sendto,recvfrom,fork,clone,vfork,mmap,security_socket_connect,security_socket_accept",
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
    try:
        time.sleep(3)
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
                str(scenario.get("command") or ""),
            ],
            capture=True,
            check=True,
        ).stdout.strip().lower()

        wait_timeout = int(scenario.get("duration_seconds") or 0) + 30
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
        trace_path,
        driver_container_name,
        driver_id,
        base_container_ids,
        windows_dir,
        metrics_path,
        window_seconds,
    )
    write_json(str(run_meta_path), run_meta)

    window_count = materialize_windows(trace_path, windows_dir, window_seconds)
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
        "repeat_id": int(repeat_id),
        "run_dir": str(run_dir),
        "window_count": int(window_count),
        "window_support": int(((summary.get("window_level") or {}).get("support")) or 0),
        "metrics_path": str(metrics_path),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["smoke", "full"], default="full")
    ap.add_argument("--scenario-set", default="default")
    ap.add_argument("--scenario-ids", default="")
    ap.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    ap.add_argument("--threshold-sweep", action="store_true", default=False)
    args = ap.parse_args()

    manifest = load_scenario_manifest(str(ROOT_DIR), args.scenario_set)
    scenarios = _select_scenarios(manifest, args.mode, args.scenario_ids)
    if not scenarios:
        raise ValueError("no scenarios selected")

    BENCHMARK_ROOT.mkdir(parents=True, exist_ok=True)
    engine = AnalysisEngine()
    executed_runs: List[Dict[str, Any]] = []

    try:
        for scenario in scenarios:
            for repeat_id in _repeat_ids(args.mode):
                print(f"[benchmark] scenario={scenario['id']} repeat={repeat_id} kind={scenario['kind']}")
                executed_runs.append(execute_run(scenario, repeat_id, int(args.window_seconds), engine))
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
        "window_seconds": int(args.window_seconds),
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
            "metric": "window_level.f1",
            "recommended_threshold": float(tuned.get("threshold", DEFAULT_THRESHOLD)),
            "selected_on": "validation_repeat_1",
            "summary_path": str(summary_path),
        }
        write_json(str(BENCHMARK_ROOT / f"recommended_threshold_{sanitize_name(args.scenario_set)}_{args.mode}.json"), recommended)

    fixed_threshold = summary.get("fixed_threshold") or {}
    tuned_threshold = summary.get("tuned_threshold") or {}
    if fixed_threshold and tuned_threshold:
        fixed_test = (fixed_threshold.get("test") or {}).get("window_level") or {}
        tuned_test = (tuned_threshold.get("test") or {}).get("window_level") or {}
        print(
            "[benchmark] fixed_threshold=%.2f fixed_f1=%.4f tuned_threshold=%.2f tuned_f1=%.4f"
            % (
                float(fixed_threshold.get("threshold", DEFAULT_THRESHOLD)),
                float(fixed_test.get("f1", 0.0)),
                float(tuned_threshold.get("threshold", DEFAULT_THRESHOLD)),
                float(tuned_test.get("f1", 0.0)),
            )
        )
    else:
        print("[benchmark] window_f1=%.4f" % float((summary.get("window_level") or {}).get("f1", 0.0)))


if __name__ == "__main__":
    main()
