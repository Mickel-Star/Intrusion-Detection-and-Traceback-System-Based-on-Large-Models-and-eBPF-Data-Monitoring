import json
import os
from typing import Any


def ensure_dir(path: str) -> None:
    if not path:
        return
    os.makedirs(path, exist_ok=True)


def ensure_parent_dir(file_path: str) -> None:
    d = os.path.dirname(os.path.abspath(file_path))
    if d:
        os.makedirs(d, exist_ok=True)


def write_text(file_path: str, content: str) -> None:
    ensure_parent_dir(file_path)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)


def write_json(file_path: str, payload: Any) -> None:
    ensure_parent_dir(file_path)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def read_json(file_path: str) -> Any:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

