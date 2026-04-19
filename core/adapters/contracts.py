"""Adapter request/response contracts for provider integrations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Literal


@dataclass(frozen=True)
class AdapterActionRequest:
    run_id: str
    target: str
    action: str
    timeout_seconds: int
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AdapterActionResult:
    provider: str
    status: Literal["success", "failed"]
    raw: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
