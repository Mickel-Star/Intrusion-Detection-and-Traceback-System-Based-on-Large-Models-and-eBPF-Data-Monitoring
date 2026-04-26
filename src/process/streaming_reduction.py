#!/usr/bin/env python3
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

import networkx as nx

from src.common.defaults import DEFAULT_WINDOW_SECONDS
from src.process.provenance_model import ProvenanceEventMapper, ProvenanceEdge


@dataclass(frozen=True)
class StreamingReductionConfig:
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    time_bin_seconds: int = 1
    edge_key_mode: str = "event_time_bin"

    @property
    def window_ns(self) -> int:
        return int(self.window_seconds) * 1_000_000_000

    @property
    def bin_ns(self) -> int:
        return max(int(self.time_bin_seconds), 1) * 1_000_000_000

    def normalized_edge_key_mode(self) -> str:
        value = str(self.edge_key_mode or "").strip().lower()
        if value in {"semantic", "event_time_bin"}:
            return value
        return "event_time_bin"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_seconds": int(self.window_seconds),
            "time_bin_seconds": int(self.time_bin_seconds),
            "edge_key_mode": self.normalized_edge_key_mode(),
        }


class StreamingReducer:
    def __init__(
        self,
        mapper: Optional[ProvenanceEventMapper] = None,
        config: Optional[StreamingReductionConfig] = None,
    ):
        self.mapper = mapper or ProvenanceEventMapper()
        self.config = config or StreamingReductionConfig()
        self._window_start_ns: Optional[int] = None
        self._graph: nx.MultiDiGraph = self._new_graph()
        self._metas: Dict[str, Dict[str, Any]] = {}

    def _new_graph(self) -> nx.MultiDiGraph:
        graph = nx.MultiDiGraph()
        graph.graph["reduction_config"] = self.config.to_dict()
        return graph

    def ingest_logs(self, logs: Iterable[Dict[str, Any]]) -> Iterator[Tuple[nx.MultiDiGraph, Dict[str, Dict[str, Any]]]]:
        for log in logs:
            g = self.ingest_log(log)
            if g is not None:
                yield g
        final = self.flush()
        if final is not None:
            yield final

    def ingest_log(self, log: Dict[str, Any]) -> Optional[Tuple[nx.MultiDiGraph, Dict[str, Dict[str, Any]]]]:
        e = self.mapper.parse_log_event(log)
        if not e:
            return None
        return self.ingest_edge(e)

    def ingest_edge(self, e: ProvenanceEdge) -> Optional[Tuple[nx.MultiDiGraph, Dict[str, Dict[str, Any]]]]:
        if self._window_start_ns is None:
            self._window_start_ns = e.timestamp_ns
        elif e.timestamp_ns - self._window_start_ns >= self.config.window_ns:
            finished = (self._graph, self._metas)
            self._reset_window(e.timestamp_ns)
            self._add_edge(e)
            return finished

        self._add_edge(e)
        return None

    def flush(self) -> Optional[Tuple[nx.MultiDiGraph, Dict[str, Dict[str, Any]]]]:
        if self._window_start_ns is None or self._graph.number_of_nodes() == 0:
            return None
        finished = (self._graph, self._metas)
        self._reset_window(None)
        return finished

    def _reset_window(self, new_start_ns: Optional[int]) -> None:
        self._window_start_ns = new_start_ns
        self._graph = self._new_graph()
        self._metas = {}

    def _time_bin(self, ts_ns: int) -> int:
        if self._window_start_ns is None:
            return 0
        return int((ts_ns - self._window_start_ns) // self.config.bin_ns) + 1

    def _add_edge(self, e: ProvenanceEdge) -> None:
        if e.src not in self._graph:
            self._graph.add_node(e.src, meta=e.src_meta)
        if e.dst not in self._graph:
            self._graph.add_node(e.dst, meta=e.dst_meta)

        self._metas[e.src] = e.src_meta
        self._metas[e.dst] = e.dst_meta

        et = str(e.edge_type)
        event_name = str(e.event_name or "")
        bin_idx = self._time_bin(e.timestamp_ns)

        found_key = None
        for key, attrs in self._graph.get_edge_data(e.src, e.dst, default={}).items():
            if self._same_reduced_edge(attrs, et, event_name, bin_idx):
                found_key = key
                break

        if found_key is None:
            segments = [{"bin": int(bin_idx), "count": 1}]
            self._graph.add_edge(
                e.src,
                e.dst,
                type=et,
                event_name=event_name,
                event_names=[event_name] if event_name else [],
                bin_idx=int(bin_idx),
                count=1,
                first_ts=e.timestamp_ns,
                last_ts=e.timestamp_ns,
                segments=segments,
            )
            return

        cur = self._graph[e.src][e.dst][found_key]
        cur["count"] = int(cur.get("count", 1)) + 1
        cur["last_ts"] = e.timestamp_ns
        event_names = list(cur.get("event_names") or [])
        if event_name and event_name not in event_names:
            event_names.append(event_name)
        cur["event_names"] = event_names
        segs = cur.get("segments") or []
        if segs and int(segs[-1].get("bin", -1)) == int(bin_idx):
            segs[-1]["count"] = int(segs[-1].get("count", 0)) + 1
        else:
            segs.append({"bin": int(bin_idx), "count": 1})
        cur["segments"] = segs

    def _same_reduced_edge(self, attrs: Dict[str, Any], edge_type: str, event_name: str, bin_idx: int) -> bool:
        if attrs.get("type") != edge_type:
            return False
        if self.config.normalized_edge_key_mode() == "semantic":
            return True
        return str(attrs.get("event_name") or "") == str(event_name or "") and int(attrs.get("bin_idx") or 0) == int(bin_idx)


def iter_reduced_edges(g: nx.MultiDiGraph) -> List[Tuple[str, str, str, int]]:
    edges = []
    for u, v, key, data in g.edges(keys=True, data=True):
        edges.append((u, v, str(data.get("type")), int(data.get("count", 1))))
    return edges
