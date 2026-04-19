"""Typed configuration for Burp MCP SSE provider."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class BurpMcpConfig:
    base_url: str = "http://127.0.0.1:9876"
    sse_path: str = "/"
    message_path_fallback: str = "/"
    connect_timeout_seconds: float = 3.0
    read_timeout_seconds: float = 30.0
    rpc_timeout_seconds: float = 8.0
    max_retries: int = 2
    debug_logging: bool = False
    lab_mode: bool = True
    scope_allowed_domains: tuple[str, ...] = field(default_factory=tuple)
    scope_denied_domains: tuple[str, ...] = field(default_factory=tuple)
    scope_allow_subdomains: bool = False
