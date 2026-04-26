from typing import Any, Dict, Tuple

import networkx as nx

from src.common.io import read_json, write_json


def serialize_window_graph(g: nx.MultiDiGraph) -> Dict[str, Any]:
    nodes = []
    for n, data in g.nodes(data=True):
        nodes.append({"id": n, "meta": (data or {}).get("meta", {})})
    edges = []
    for u, v, k, data in g.edges(keys=True, data=True):
        d = data or {}
        edges.append(
            {
                "src": u,
                "dst": v,
                "type": str(d.get("type")),
                "event_name": str(d.get("event_name") or ""),
                "event_names": list(d.get("event_names") or []),
                "bin_idx": int(d.get("bin_idx", 0) or 0),
                "count": int(d.get("count", 1)),
                "first_ts": int(d.get("first_ts", 0)),
                "last_ts": int(d.get("last_ts", 0)),
                "segments": d.get("segments") or [],
            }
        )
    return {"metadata": {"reduction_config": dict(g.graph.get("reduction_config") or {})}, "nodes": nodes, "edges": edges}


def deserialize_window_graph(payload: Dict[str, Any]) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    for n in payload.get("nodes", []) or []:
        g.add_node(n.get("id"), meta=n.get("meta", {}) or {})
    for e in payload.get("edges", []) or []:
        g.add_edge(
            e.get("src"),
            e.get("dst"),
            type=str(e.get("type")),
            event_name=str(e.get("event_name") or ""),
            event_names=list(e.get("event_names") or []),
            bin_idx=int(e.get("bin_idx", 0) or 0),
            count=int(e.get("count", 1)),
            first_ts=int(e.get("first_ts", 0)),
            last_ts=int(e.get("last_ts", 0)),
            segments=e.get("segments") or [],
        )
    metadata = payload.get("metadata") or {}
    if isinstance(metadata, dict):
        g.graph.update(metadata)
    return g


def dump_window_graph(path: str, g: nx.MultiDiGraph) -> None:
    write_json(path, serialize_window_graph(g))


def load_window_graph(path: str) -> nx.MultiDiGraph:
    payload = read_json(path)
    return deserialize_window_graph(payload)
