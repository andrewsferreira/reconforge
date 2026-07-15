"""Burp MCP provider models and contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BurpSseEvent:
    event: str
    data: str
    event_id: str = ""


@dataclass
class BurpCapability:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    enabled: bool = False
    reason: str = ""


@dataclass
class BurpSessionState:
    base_url: str
    sse_connected: bool = False
    session_id: str = ""
    message_endpoint: str = ""
    retries_used: int = 0
    transport_stable: bool = False


@dataclass
class BurpRpcResult:
    request_id: int
    ok: bool
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


@dataclass
class NormalizedBurpHttpRecord:
    url: str = ""
    host: str = ""
    method: str = ""
    status_code: int = 0
    response_body_length: int = 0
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    provider: str = "burp_mcp"
    tool_name: str = ""
    evidence_source: str = ""


@dataclass
class BurpProviderState:
    session: BurpSessionState
    discovered_tools: list[BurpCapability] = field(default_factory=list)
    enabled_tools: list[str] = field(default_factory=list)
    disabled_tools: list[str] = field(default_factory=list)
