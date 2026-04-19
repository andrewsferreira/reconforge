"""Burp MCP transport client preserving SSE + async JSON-RPC behavior."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from core.adapters.burp.capabilities import build_capability_map, classify_capabilities
from core.adapters.burp.config import BurpMcpConfig
from core.adapters.burp.connection import BurpSseConnection
from core.adapters.burp.exceptions import BurpNoCapabilitiesError
from core.adapters.burp.models import BurpCapability
from core.adapters.burp.policy import BurpCapabilityPolicy
from core.adapters.burp.rpc import BurpJsonRpcClient

LOGGER = logging.getLogger(__name__)


class BurpMcpClient:
    def __init__(self, config: BurpMcpConfig, policy: BurpCapabilityPolicy):
        self.config = config
        self.policy = policy
        self.connection = BurpSseConnection(config)
        self.rpc = BurpJsonRpcClient(self.connection)
        self._capabilities: Dict[str, BurpCapability] = {}

    def connect(self) -> None:
        self.connection.connect()

    def close(self) -> None:
        self.connection.close()

    def discover_capabilities(self) -> List[BurpCapability]:
        payload = self.rpc.tools_list()
        raw_tools = payload.get("tools", [])
        if not isinstance(raw_tools, list):
            raise BurpNoCapabilitiesError("tools/list returned non-list tools payload")

        enabled_tools = {tool for tool in self.policy.enabled_tools if self.policy.is_allowed(tool)}
        capabilities = classify_capabilities(raw_tools, enabled_tools)
        if not capabilities:
            raise BurpNoCapabilitiesError("Burp reachable but no capabilities returned")

        self._capabilities = build_capability_map(capabilities)
        LOGGER.info(json.dumps({"event": "burp_tool_discovery", "tool_count": len(capabilities)}))
        return capabilities

    def has_capability(self, tool_name: str) -> bool:
        cap = self._capabilities.get(tool_name)
        return bool(cap and cap.enabled)

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self.rpc.tools_call(tool_name, arguments)

    @property
    def capability_map(self) -> Dict[str, BurpCapability]:
        return dict(self._capabilities)
