"""JSON serialization helpers for reporting artifacts."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any


def to_jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return {k: to_jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    return value


def dump_json(value: Any) -> str:
    return json.dumps(to_jsonable(value), indent=2, sort_keys=True)
