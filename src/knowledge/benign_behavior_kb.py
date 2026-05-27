#!/usr/bin/env python3
import os
import sqlite3
from typing import Any, Dict, Iterable, List, Optional, Tuple

from gensim.models import Word2Vec

from src.process.provenance_model import tokenize_identifier


class BenignBehaviorKnowledgeBase:
    def __init__(
        self,
        db_path: str = "./data/bbk.sqlite",
        model_path: str = "./data/models/bbk_word2vec.model",
        vector_dim: int = 64,
        min_count: int = 1,
        epochs: int = 10,
    ):
        self.db_path = db_path
        self.model_path = model_path
        self.vector_dim = int(vector_dim)
        self.min_count = int(min_count)
        self.epochs = int(epochs)

        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.model_path)), exist_ok=True)

        self.conn = sqlite3.connect(self.db_path)
        self._init_schema()
        self.w2v: Optional[Word2Vec] = None
        self._load_or_init_model()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS edge_freq (
                src TEXT NOT NULL,
                dst TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                total_freq INTEGER NOT NULL,
                PRIMARY KEY (src, dst, edge_type)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS node_degree (
                node TEXT PRIMARY KEY,
                out_freq INTEGER NOT NULL,
                in_freq INTEGER NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS node_meta (
                node TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                pathname TEXT,
                name TEXT,
                src_ip TEXT,
                dst_ip TEXT
            )
            """
        )
        self.conn.commit()

    def _load_or_init_model(self) -> None:
        if os.path.exists(self.model_path):
            self.w2v = Word2Vec.load(self.model_path)
            self.vector_dim = int(self.w2v.vector_size)
            return
        self.w2v = Word2Vec(vector_size=self.vector_dim, window=5, min_count=self.min_count, workers=4)

    def update_from_edges(self, edges: Iterable[Tuple[str, str, str, int]], metas: Dict[str, Dict[str, Any]]) -> None:
        cur = self.conn.cursor()

        unspec_nodes: set[str] = set()
        for node, meta in metas.items():
            if meta.get("is_unspec_net"):
                unspec_nodes.add(str(node))

        for node, meta in metas.items():
            if str(node) in unspec_nodes:
                continue
            entity_type = "UNKNOWN"
            if node.startswith("proc:"):
                entity_type = "Process"
            elif node.startswith("file:"):
                entity_type = "File"
            elif node.startswith("net:"):
                entity_type = "Socket"

            cur.execute(
                """
                INSERT INTO node_meta(node, entity_type, pathname, name, src_ip, dst_ip)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(node) DO UPDATE SET
                    entity_type=excluded.entity_type,
                    pathname=COALESCE(excluded.pathname, node_meta.pathname),
                    name=COALESCE(excluded.name, node_meta.name),
                    src_ip=COALESCE(excluded.src_ip, node_meta.src_ip),
                    dst_ip=COALESCE(excluded.dst_ip, node_meta.dst_ip)
                """,
                (
                    node,
                    entity_type,
                    meta.get("pathname"),
                    meta.get("name"),
                    meta.get("src_ip"),
                    meta.get("dst_ip"),
                ),
            )

        for src, dst, edge_type, count in edges:
            if str(src) in unspec_nodes or str(dst) in unspec_nodes:
                continue
            count = int(count)
            cur.execute(
                """
                INSERT INTO edge_freq(src, dst, edge_type, total_freq)
                VALUES(?,?,?,?)
                ON CONFLICT(src, dst, edge_type) DO UPDATE SET
                    total_freq = total_freq + excluded.total_freq
                """,
                (src, dst, edge_type, count),
            )

            cur.execute(
                """
                INSERT INTO node_degree(node, out_freq, in_freq)
                VALUES(?,?,?)
                ON CONFLICT(node) DO UPDATE SET
                    out_freq = out_freq + excluded.out_freq,
                    in_freq = in_freq + excluded.in_freq
                """,
                (src, count, 0),
            )
            cur.execute(
                """
                INSERT INTO node_degree(node, out_freq, in_freq)
                VALUES(?,?,?)
                ON CONFLICT(node) DO UPDATE SET
                    out_freq = out_freq + excluded.out_freq,
                    in_freq = in_freq + excluded.in_freq
                """,
                (dst, 0, count),
            )

        self.conn.commit()

    def update_word2vec_from_metas(self, metas: Dict[str, Dict[str, Any]]) -> None:
        if self.w2v is None:
            self._load_or_init_model()
        assert self.w2v is not None

        sentences: List[List[str]] = []
        for meta in metas.values():
            if meta.get("is_unspec_net"):
                continue
            base = meta.get("pathname") or meta.get("name") or ""
            toks = tokenize_identifier(base)
            if toks:
                sentences.append(toks)

        if not sentences:
            return

        if not self.w2v.wv.key_to_index:
            self.w2v.build_vocab(sentences)
        else:
            self.w2v.build_vocab(sentences, update=True)

        self.w2v.train(sentences, total_examples=len(sentences), epochs=self.epochs)
        self.w2v.save(self.model_path)

    def get_total_freq(self, src: str, dst: str, edge_type: str) -> int:
        cur = self.conn.cursor()
        row = cur.execute(
            "SELECT total_freq FROM edge_freq WHERE src=? AND dst=? AND edge_type=?",
            (src, dst, edge_type),
        ).fetchone()
        return int(row[0]) if row else 0

    def get_out_in(self, node: str) -> Tuple[int, int]:
        cur = self.conn.cursor()
        row = cur.execute("SELECT out_freq, in_freq FROM node_degree WHERE node=?", (node,)).fetchone()
        if not row:
            return (0, 0)
        return (int(row[0]), int(row[1]))

    def support(self, src: str, dst: str, edge_type: str) -> float:
        tf = self.get_total_freq(src, dst, edge_type)
        out_f, _ = self.get_out_in(src)
        denom = max(out_f, 1)
        s = float(tf) / float(denom)
        if s <= 0:
            return 1e-9
        return min(1.0, s)

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

