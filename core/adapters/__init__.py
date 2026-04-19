"""Adapter contracts and provider boundaries."""

from core.adapters.base_adapter import ProviderAdapter
from core.adapters.contracts import AdapterActionRequest, AdapterActionResult
from core.adapters.mcp_adapter import McpAdapterConfig, McpClientAdapter

__all__ = [
    "ProviderAdapter",
    "AdapterActionRequest",
    "AdapterActionResult",
    "McpAdapterConfig",
    "McpClientAdapter",
]
