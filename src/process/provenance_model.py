#!/usr/bin/env python3
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import networkx as nx
from src.common.text import tokenize_identifier


def parse_ip_port(addr: str) -> Tuple[str, int]:
    if not addr:
        return ("", 0)
    addr = str(addr).strip()
    m6 = re.match(r"^\[([0-9a-fA-F:]+)\](?::([0-9]{1,5}))?$", addr)
    if m6:
        ip = m6.group(1)
        port = int(m6.group(2)) if m6.group(2) else 0
        return (ip, port)
    m4 = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?::([0-9]{1,5}))?", addr)
    if m4:
        ip = m4.group(1)
        port = int(m4.group(2)) if m4.group(2) else 0
        return (ip, port)
    return (addr, 0)


@dataclass(frozen=True)
class ProvenanceEdge:
    src: str
    dst: str
    edge_type: str
    event_name: str
    timestamp_ns: int
    src_meta: Dict[str, Any]
    dst_meta: Dict[str, Any]


class ProvenanceEventMapper:
    def __init__(self):
        self.event_semantics = {
            "read": ("Read", "backward"),
            "recvfrom": ("Receive", "backward"),
            "mmap": ("Mmap", "backward"),
            "write": ("Write", "forward"),
            "sendto": ("Send", "forward"),
            "execve": ("Execute", "forward"),
            "sched_process_exec": ("Execute", "forward"),
            "fork": ("Fork", "forward"),
            "vfork": ("Fork", "forward"),
            "clone": ("Fork", "forward"),
            "connect": ("Send", "forward"),
            "security_socket_connect": ("Send", "forward"),
            "accept": ("Receive", "backward"),
            "security_socket_accept": ("Receive", "backward"),
            "openat": ("Write", "forward"),
            "close": ("Write", "forward"),
        }
        self._fd_files: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
        self._fd_nets: Dict[Tuple[str, int, str], Dict[str, Any]] = {}

    def _container_scope(self, container_id: Any) -> str:
        value = str(container_id or "").strip().lower()
        return value[:12] if value else "host"

    def parse_log_event(self, log: Dict[str, Any]) -> Optional[ProvenanceEdge]:
        event = (log.get("event") or "").strip()
        if event not in self.event_semantics:
            return None

        edge_type, direction = self.event_semantics[event]
        pid = int(log.get("pid", 0))
        comm = log.get("comm", "unknown")
        args = log.get("args", {}) or {}
        container_id = log.get("container_id")
        container_scope = self._container_scope(container_id)

        timestamp_ns = int(float(log.get("timestamp", 0.0)) * 1e9)

        proc_uuid = f"container:{container_scope}:pid:{pid}"
        proc_node = f"proc:{proc_uuid}"

        proc_path = str(args.get("pathname") or args.get("path") or "")
        proc_meta: Dict[str, Any] = {
            "uuid": proc_uuid,
            "pathname": proc_path,
            "name": comm,
            "pid": pid,
            "container_id": container_id,
            "container_image": log.get("container_image"),
            "pod_name": log.get("pod_name"),
        }

        if event in {"openat", "execve", "sched_process_exec", "read", "write", "close", "mmap"}:
            resolved = self._resolve_file_object(event, args, container_scope, pid, log)
            if resolved is None:
                return None
            obj_node, obj_meta = resolved

        elif event in {"connect", "security_socket_connect", "accept", "security_socket_accept", "sendto", "recvfrom"}:
            resolved = self._resolve_net_object(event, args, container_scope, pid)
            if resolved is None:
                return None
            obj_node, obj_meta = resolved

        elif event in {"fork", "vfork", "clone"}:
            child_pid = args.get("child_pid")
            if not child_pid:
                return None
            child_uuid = f"container:{container_scope}:pid:{child_pid}"
            obj_node = f"proc:{child_uuid}"
            obj_meta = {
                "uuid": child_uuid,
                "pathname": "",
                "name": f"child_pid_{child_pid}",
                "pid": int(child_pid),
                "container_id": container_id,
                "container_image": log.get("container_image"),
                "pod_name": log.get("pod_name"),
            }

        if not obj_node:
            return None

        if direction == "backward":
            edge = ProvenanceEdge(
                src=obj_node,
                dst=proc_node,
                edge_type=edge_type,
                event_name=event,
                timestamp_ns=timestamp_ns,
                src_meta=obj_meta,
                dst_meta=proc_meta,
            )
            self._cleanup_after_event(event, args, container_scope, pid)
            return edge

        edge = ProvenanceEdge(
            src=proc_node,
            dst=obj_node,
            edge_type=edge_type,
            event_name=event,
            timestamp_ns=timestamp_ns,
            src_meta=proc_meta,
            dst_meta=obj_meta,
        )
        self._cleanup_after_event(event, args, container_scope, pid)
        return edge

    def _fd_value(self, args: Dict[str, Any], *names: str) -> str:
        for name in names:
            value = args.get(name)
            if value is not None and str(value).strip():
                return str(value).strip()
        return ""

    def _fd_key(self, container_scope: str, pid: int, fd: str) -> Tuple[str, int, str]:
        return (str(container_scope), int(pid), str(fd))

    def _file_from_path(self, path: str, args: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        inode = str(args.get("inode") or "")
        file_uuid = f"{path}|inode:{inode}" if inode else path
        return f"file:{file_uuid}", {"uuid": file_uuid, "pathname": path, "name": path}

    def _resolve_file_object(
        self,
        event: str,
        args: Dict[str, Any],
        container_scope: str,
        pid: int,
        log: Dict[str, Any],
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        path = str(args.get("pathname") or args.get("path") or args.get("mountpoint") or "")
        fd = self._fd_value(args, "fd")

        if path:
            node, meta = self._file_from_path(path, args)
            if event == "openat":
                returned_fd = int(log.get("ret", -1))
                if returned_fd >= 0:
                    self._fd_files[self._fd_key(container_scope, pid, str(returned_fd))] = {
                        "node": node,
                        "meta": meta,
                    }
            return node, meta

        if fd:
            file_entry = self._fd_files.get(self._fd_key(container_scope, pid, fd))
            if file_entry:
                return str(file_entry["node"]), dict(file_entry["meta"])

            if event == "close":
                net_entry = self._fd_nets.get(self._fd_key(container_scope, pid, fd))
                if net_entry:
                    return str(net_entry["node"]), dict(net_entry["meta"])

            path = f"fd:{fd}_container:{container_scope}_pid:{pid}"
            return self._file_from_path(path, args)

        return None

    def _addr_arg(self, args: Dict[str, Any], *names: str) -> Any:
        for name in names:
            value = args.get(name)
            if value:
                normalized = self._normalize_addr(value)
                if normalized:
                    return value
        return ""

    def _net_from_addr(self, remote_raw: Any, local_raw: Any, args: Dict[str, Any], pid: int) -> Tuple[str, Dict[str, Any]]:
        remote_addr = self._normalize_addr(remote_raw)
        local_addr = self._normalize_addr(local_raw)
        dst_ip, dst_port = parse_ip_port(remote_addr)
        src_ip, src_port = parse_ip_port(local_addr)
        if not dst_ip:
            dst_ip, dst_port = ("unknown", 0)
        if not src_ip:
            src_ip, src_port = ("pid", pid)
        proto = str(args.get("protocol") or args.get("proto") or "tcp").lower()
        net_uuid = f"{proto}:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        meta = {
            "uuid": net_uuid,
            "src_ip": str(src_ip),
            "dst_ip": str(dst_ip),
            "name": f"{src_ip}:{src_port}->{dst_ip}:{dst_port}",
        }
        return f"net:{net_uuid}", meta

    def _resolve_net_object(
        self,
        event: str,
        args: Dict[str, Any],
        container_scope: str,
        pid: int,
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        fd = self._fd_value(args, "sockfd", "fd")
        fd_key = self._fd_key(container_scope, pid, fd) if fd else None

        remote_raw = self._addr_arg(args, "remote_addr", "dest_addr", "addr", "dst")
        if event in {"accept", "security_socket_accept", "recvfrom"}:
            remote_raw = self._addr_arg(args, "src_addr", "remote_addr", "addr", "dst")
        local_raw = self._addr_arg(args, "local_addr", "src")

        if not remote_raw and fd_key is not None:
            cached = self._fd_nets.get(fd_key)
            if cached:
                return str(cached["node"]), dict(cached["meta"])

        node, meta = self._net_from_addr(remote_raw, local_raw, args, pid)
        if fd_key is not None and meta.get("dst_ip") not in {"", "unknown"}:
            self._fd_nets[fd_key] = {"node": node, "meta": meta}
        return node, meta

    def _cleanup_after_event(self, event: str, args: Dict[str, Any], container_scope: str, pid: int) -> None:
        if event != "close":
            return
        fd = self._fd_value(args, "fd", "sockfd")
        if not fd:
            return
        key = self._fd_key(container_scope, pid, fd)
        self._fd_files.pop(key, None)
        self._fd_nets.pop(key, None)

    def _normalize_addr(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, dict):
            family = str(value.get("sa_family") or "").upper()
            if family == "AF_UNSPEC":
                return ""
            if "sun_path" in value:
                return str(value.get("sun_path") or "")
            if "sin_addr" in value:
                addr = str(value.get("sin_addr") or "")
                port = str(value.get("sin_port") or "")
                if addr and port and port != "0":
                    return f"{addr}:{port}"
                return addr
            if "sin6_addr" in value:
                addr = str(value.get("sin6_addr") or "")
                port = str(value.get("sin6_port") or "")
                if addr and port and port != "0":
                    return f"[{addr}]:{port}"
                return addr
            return " ".join([f"{k}:{v}" for k, v in value.items()])
        return str(value)


def rarity_score_from_supports(supports: List[float]) -> float:
    score = 0.0
    for s in supports:
        s = max(float(s), 1e-9)
        score += -math.log2(s)
    return score


def collect_keywords(meta: Dict[str, Any]) -> List[str]:
    kws: List[str] = []
    if not meta:
        return kws
    for key in ("pathname", "name", "src_ip", "dst_ip"):
        val = meta.get(key, "")
        if not val:
            continue
        kws.extend(tokenize_identifier(val))
    return kws


class RarePathSelector:
    def __init__(self, k1: int = 10, k2: int = 10):
        self.k1 = int(k1)
        self.k2 = int(k2)

    def select_with_chains(self, g: nx.MultiDiGraph, seed: str, support_fn) -> List[Dict[str, Any]]:
        if seed not in g:
            return []

        results: List[Dict[str, Any]] = []
        frontier: List[Tuple[str, List[Tuple[str, str, str, str]]]] = [(seed, [])]
        visited_states = set([(seed, 0)])

        for _ in range(self.k1):
            next_frontier: List[Tuple[str, List[Tuple[str, str, str, str]]]] = []
            for node, edge_chain in frontier:
                for _, nbr, key, data in g.out_edges(node, keys=True, data=True):
                    et = str(data.get("type"))
                    chain2 = edge_chain + [(node, et, nbr, "out")]
                    state = (nbr, len(chain2))
                    if state not in visited_states:
                        visited_states.add(state)
                        next_frontier.append((nbr, chain2))
                        supports = []
                        for u, t, v, direction in chain2:
                            if direction == "out":
                                supports.append(float(support_fn(u, v, t)))
                            else:
                                supports.append(float(support_fn(v, u, t)))
                        score = rarity_score_from_supports(supports)
                        text = self._chain_to_text(g, seed, chain2)
                        kws = []
                        kws.extend(collect_keywords(g.nodes[seed].get("meta", {})))
                        kws.extend(collect_keywords(g.nodes[nbr].get("meta", {})))
                        results.append(
                            {
                                "text": text,
                                "score": score,
                                "keywords": list(dict.fromkeys(kws)),
                                "chain": chain2,
                            }
                        )

                for nbr, _, key, data in g.in_edges(node, keys=True, data=True):
                    et = str(data.get("type"))
                    chain2 = edge_chain + [(node, et, nbr, "in")]
                    state = (nbr, len(chain2))
                    if state not in visited_states:
                        visited_states.add(state)
                        next_frontier.append((nbr, chain2))
                        supports = []
                        for u, t, v, direction in chain2:
                            if direction == "out":
                                supports.append(float(support_fn(u, v, t)))
                            else:
                                supports.append(float(support_fn(v, u, t)))
                        score = rarity_score_from_supports(supports)
                        text = self._chain_to_text(g, seed, chain2)
                        kws = []
                        kws.extend(collect_keywords(g.nodes[seed].get("meta", {})))
                        kws.extend(collect_keywords(g.nodes[nbr].get("meta", {})))
                        results.append(
                            {
                                "text": text,
                                "score": score,
                                "keywords": list(dict.fromkeys(kws)),
                                "chain": chain2,
                            }
                        )
            frontier = next_frontier

        results.sort(key=lambda x: float(x.get("score", 0.0)), reverse=True)
        return results[: self.k2]

    def _chain_to_text(self, g: nx.MultiDiGraph, seed: str, chain: List[Tuple[str, str, str, str]]) -> str:
        parts: List[str] = []
        seed_meta = g.nodes[seed].get("meta", {})
        seed_name = seed_meta.get("pathname") or seed_meta.get("name") or seed
        parts.append(str(seed_name))
        for _, et, v, direction in chain:
            v_meta = g.nodes[v].get("meta", {})
            v_name = v_meta.get("pathname") or v_meta.get("name") or v
            parts.append(f"{et}{'<-' if direction == 'in' else '->'}")
            parts.append(str(v_name))
        return " ".join(parts)
