from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


ITEM_IDS = ["sku-001", "sku-002", "sku-003"]
SEARCH_TERMS = ["sku", "alice", "bob", "container", "threat", "provenance", "audit"]


def profile_catalog() -> dict[str, dict[str, Any]]:
    return {
        "health_idle_poll": {
            "description": "/health and /api/items low-frequency polling"
        },
        "auth_read_session": {
            "description": "login, profile read, recent orders, logout"
        },
        "business_write_transaction": {
            "description": "login, create orders, read back orders, logout"
        },
        "search_lookup_query": {
            "description": "search and order lookup workload"
        },
        "burst_then_idle": {
            "description": "short active bursts followed by idle polling"
        },
    }


def run_profile(profile_id: str, *, base_url: str, duration_seconds: float, seed: int) -> None:
    rng = random.Random(int(seed))
    deadline = time.monotonic() + max(float(duration_seconds), 0.0)
    runners = {
        "health_idle_poll": _health_idle_poll,
        "auth_read_session": _auth_read_session,
        "business_write_transaction": _business_write_transaction,
        "search_lookup_query": _search_lookup_query,
        "burst_then_idle": _burst_then_idle,
    }
    runner = runners.get(str(profile_id))
    if runner is None:
        raise RuntimeError(f"unsupported profile: {profile_id}")
    while deadline > time.monotonic():
        runner(str(base_url).rstrip("/"), deadline, rng)


def _request(method: str, base_url: str, path: str, payload: dict[str, Any] | None = None, token: str = "") -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base_url + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read().decode("utf-8", "ignore")
            if not text:
                return {}
            try:
                return json.loads(text)
            except Exception:
                return {"raw": text}
    except urllib.error.HTTPError as exc:
        try:
            text = exc.read().decode("utf-8", "ignore")
            return json.loads(text) if text else {}
        except Exception:
            return {}
    except Exception:
        return {}


def _sleep_between(rng: random.Random, low_seconds: float, high_seconds: float, deadline: float) -> None:
    remaining = max(deadline - time.monotonic(), 0.0)
    if remaining <= 0:
        return
    time.sleep(min(rng.uniform(float(low_seconds), float(high_seconds)), remaining))


def _login(base_url: str, username: str) -> str:
    payload = _request("POST", base_url, "/api/login", {"username": username, "password": "password"})
    return str(payload.get("token") or "")


def _logout(base_url: str, token: str) -> None:
    if token:
        _request("POST", base_url, "/api/logout", token=token)


def _me(base_url: str, token: str) -> None:
    if token:
        _request("GET", base_url, "/api/me", token=token)


def _items(base_url: str) -> None:
    _request("GET", base_url, "/api/items")


def _health(base_url: str) -> None:
    _request("GET", base_url, "/health")


def _search(base_url: str, term: str) -> None:
    _request("GET", base_url, f"/api/search?{urllib.parse.urlencode({'q': term})}")


def _order(base_url: str, customer: str, rng: random.Random) -> int:
    payload = _request(
        "POST",
        base_url,
        "/api/order",
        {"customer": customer, "item": rng.choice(ITEM_IDS), "quantity": rng.randint(1, 3)},
    )
    try:
        return int(payload.get("order_id") or 0)
    except Exception:
        return 0


def _order_lookup(base_url: str, order_id: int) -> None:
    if order_id > 0:
        _request("GET", base_url, f"/api/order/{int(order_id)}")


def _health_idle_poll(base_url: str, deadline: float, rng: random.Random) -> None:
    _health(base_url)
    _items(base_url)
    _sleep_between(rng, 3.0, 5.0, deadline)


def _auth_read_session(base_url: str, deadline: float, rng: random.Random) -> None:
    username = rng.choice(["alice", "bob"])
    token = _login(base_url, username)
    _sleep_between(rng, 0.2, 0.5, deadline)
    _me(base_url, token)
    _sleep_between(rng, 0.2, 0.5, deadline)
    _items(base_url)
    _sleep_between(rng, 0.2, 0.5, deadline)
    _logout(base_url, token)


def _business_write_transaction(base_url: str, deadline: float, rng: random.Random) -> None:
    username = rng.choice(["alice", "bob"])
    token = _login(base_url, username)
    _sleep_between(rng, 0.2, 0.5, deadline)
    order_ids = []
    for _ in range(rng.randint(1, 3)):
        order_ids.append(_order(base_url, username, rng))
        _sleep_between(rng, 0.2, 0.6, deadline)
    for order_id in order_ids:
        _order_lookup(base_url, order_id)
        _sleep_between(rng, 0.2, 0.6, deadline)
    _me(base_url, token)
    _logout(base_url, token)


def _search_lookup_query(base_url: str, deadline: float, rng: random.Random) -> None:
    order_id = _order(base_url, rng.choice(["alice", "bob"]), rng)
    for _ in range(4):
        if deadline <= time.monotonic():
            break
        _search(base_url, rng.choice(SEARCH_TERMS))
        _sleep_between(rng, 0.2, 0.6, deadline)
        _order_lookup(base_url, order_id)
        _sleep_between(rng, 0.2, 0.6, deadline)


def _burst_then_idle(base_url: str, deadline: float, rng: random.Random) -> None:
    burst_deadline = min(deadline, time.monotonic() + 30.0)
    while burst_deadline > time.monotonic():
        _items(base_url)
        _search(base_url, rng.choice(SEARCH_TERMS))
        if rng.random() < 0.35:
            _order(base_url, "alice", rng)
        _sleep_between(rng, 0.1, 0.3, burst_deadline)

    idle_deadline = min(deadline, time.monotonic() + 30.0)
    while idle_deadline > time.monotonic():
        _health(base_url)
        _items(base_url)
        _sleep_between(rng, 3.0, 5.0, idle_deadline)
