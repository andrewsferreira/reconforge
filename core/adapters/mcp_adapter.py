"""MCP provider adapter (adapter-only model).

This adapter intentionally exposes only a data-provider boundary. It does not
perform workflow sequencing, policy checks, or dynamic tool chaining decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict

from core.adapters.base_adapter import ProviderAdapter
from core.adapters.contracts import AdapterActionRequest, AdapterActionResult

McpInvoker = Callable[[str, str, Dict[str, Any], int], Dict[str, Any]]


@dataclass(frozen=True)
class McpAdapterConfig:
    provider_name: str
    timeout_seconds: int = 120


class McpClientAdapter(ProviderAdapter):
    adapter_id = "mcp"
    max_retries = 2

    def __init__(self, config: McpAdapterConfig, invoker: McpInvoker, **kwargs):
        super().__init__(**kwargs)
        self.config = config
        self._invoker = invoker

    def execute(self, request: AdapterActionRequest) -> AdapterActionResult:
        payload = self._invoker(
            self.config.provider_name,
            request.action,
            request.parameters,
            min(request.timeout_seconds, self.config.timeout_seconds),
        )
        if not isinstance(payload, dict):
            raise ValueError("MCP adapter invoker must return dict payload")

        status = str(payload.get("status", "success")).lower()
        if status not in {"success", "failed"}:
            status = "failed"

        raw = payload.get("data", payload)
        if not isinstance(raw, dict):
            raw = {"value": raw}

        return AdapterActionResult(
            provider=f"mcp:{self.config.provider_name}",
            status=status,  # type: ignore[arg-type]
            raw=raw,
            error=str(payload.get("error", "")),
            metadata={"provider_name": self.config.provider_name},
        )
