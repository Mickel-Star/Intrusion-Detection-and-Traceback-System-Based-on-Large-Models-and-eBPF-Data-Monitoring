from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from src.common.defaults import DEFAULT_ALERT_THRESHOLD
from src.common.io import read_json


ALLOWED_ROLES: tuple[str, ...] = ("attacker", "benign", "target", "target_dsock", "c2")
POSITIVE_LABEL = "positive"
NEGATIVE_LABEL = "negative"
IGNORED_LABEL = "ignored"
DEFAULT_THRESHOLD = DEFAULT_ALERT_THRESHOLD
DEFAULT_SWEEP_THRESHOLDS: tuple[float, ...] = tuple(round(step * 0.05, 2) for step in range(1, 20))


def normalize_container_id(container_id: str) -> str:
    if not container_id:
        return ""
    return str(container_id).strip().lower()


def short_container_id(container_id: str) -> str:
    return normalize_container_id(container_id)[:12]


def sanitize_name(value: str) -> str:
    out = []
    for ch in str(value or ""):
        if ch.isalnum() or ch in ("-", "_"):
            out.append(ch)
        else:
            out.append("-")
    text = "".join(out).strip("-")
    return text or "unknown"


def role_label(role: str, positive_roles: Sequence[str], negative_roles: Sequence[str]) -> str:
    if role in set(positive_roles or []):
        return POSITIVE_LABEL
    if role in set(negative_roles or []):
        return NEGATIVE_LABEL
    return IGNORED_LABEL


def _validate_roles(roles: Iterable[str], field_name: str) -> List[str]:
    values: List[str] = []
    seen = set()
    for role in roles or []:
        role_name = str(role or "").strip()
        if not role_name:
            continue
        if role_name not in ALLOWED_ROLES:
            raise ValueError(f"{field_name} contains unsupported role: {role_name}")
        if role_name not in seen:
            seen.add(role_name)
            values.append(role_name)
    return values


def validate_scenario_manifest(payload: Dict[str, Any]) -> Dict[str, Any]:
    scenarios = payload.get("scenarios") or []
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("scenario manifest must contain a non-empty scenarios list")

    scenario_ids = set()
    validated: List[Dict[str, Any]] = []
    for raw in scenarios:
        if not isinstance(raw, dict):
            raise ValueError("scenario entry must be an object")

        scenario_id = str(raw.get("id") or "").strip()
        if not scenario_id:
            raise ValueError("scenario id is required")
        if scenario_id in scenario_ids:
            raise ValueError(f"duplicate scenario id: {scenario_id}")
        scenario_ids.add(scenario_id)

        kind = str(raw.get("kind") or "").strip().lower()
        if kind not in {"attack", "benign"}:
            raise ValueError(f"{scenario_id}: kind must be attack or benign")

        target_service = str(raw.get("target_service") or "").strip()
        command = str(raw.get("command") or "").strip()
        duration_seconds = int(raw.get("duration_seconds") or 0)
        if not target_service:
            raise ValueError(f"{scenario_id}: target_service is required")
        if not command:
            raise ValueError(f"{scenario_id}: command is required")
        if duration_seconds <= 0:
            raise ValueError(f"{scenario_id}: duration_seconds must be > 0")

        positive_roles = _validate_roles(raw.get("positive_roles") or [], f"{scenario_id}.positive_roles")
        negative_roles = _validate_roles(raw.get("negative_roles") or [], f"{scenario_id}.negative_roles")
        overlap = set(positive_roles) & set(negative_roles)
        if overlap:
            raise ValueError(f"{scenario_id}: roles cannot be both positive and negative: {sorted(overlap)}")

        driver_role = str(raw.get("driver_role") or ("attacker" if kind == "attack" else "benign")).strip()
        if driver_role not in ALLOWED_ROLES:
            raise ValueError(f"{scenario_id}: unsupported driver_role: {driver_role}")

        validated.append(
            {
                "id": scenario_id,
                "kind": kind,
                "target_service": target_service,
                "command": command,
                "duration_seconds": duration_seconds,
                "driver_role": driver_role,
                "positive_roles": positive_roles,
                "negative_roles": negative_roles,
                "description": str(raw.get("description") or "").strip(),
            }
        )

    return {
        "scenario_set": str(payload.get("scenario_set") or "default"),
        "allowed_roles": list(ALLOWED_ROLES),
        "scenarios": validated,
    }


def resolve_scenario_manifest(repo_root: str, scenario_set: str) -> Path:
    candidate = Path(scenario_set)
    if candidate.exists():
        return candidate.resolve()
    return Path(repo_root, "config", f"benchmark_scenarios.{scenario_set}.json").resolve()


def load_scenario_manifest(repo_root: str, scenario_set: str) -> Dict[str, Any]:
    manifest_path = resolve_scenario_manifest(repo_root, scenario_set)
    if not manifest_path.exists():
        raise FileNotFoundError(f"scenario manifest not found: {manifest_path}")
    payload = read_json(str(manifest_path))
    validated = validate_scenario_manifest(payload)
    validated["manifest_path"] = str(manifest_path)
    return validated


def validate_labels_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    containers = payload.get("containers") or []
    if not isinstance(containers, list):
        raise ValueError("labels payload containers must be a list")

    positive_roles = _validate_roles(payload.get("positive_roles") or [], "labels.positive_roles")
    negative_roles = _validate_roles(payload.get("negative_roles") or [], "labels.negative_roles")
    overlap = set(positive_roles) & set(negative_roles)
    if overlap:
        raise ValueError(f"labels payload role overlap: {sorted(overlap)}")

    validated_containers: List[Dict[str, Any]] = []
    seen = set()
    for raw in containers:
        if not isinstance(raw, dict):
            raise ValueError("label container entry must be an object")
        role = str(raw.get("role") or "").strip()
        if role not in ALLOWED_ROLES:
            raise ValueError(f"unsupported label role: {role}")
        container_id = normalize_container_id(raw.get("container_id") or "")
        container_name = str(raw.get("container_name") or "").strip()
        key = (role, short_container_id(container_id), container_name)
        if key in seen:
            continue
        seen.add(key)
        validated_containers.append(
            {
                "role": role,
                "container_id": container_id,
                "container_name": container_name,
                "label": str(raw.get("label") or role_label(role, positive_roles, negative_roles)),
            }
        )

    return {
        "schema_version": int(payload.get("schema_version") or 1),
        "scenario_id": str(payload.get("scenario_id") or "").strip(),
        "kind": str(payload.get("kind") or "").strip().lower(),
        "positive_roles": positive_roles,
        "negative_roles": negative_roles,
        "containers": validated_containers,
    }
