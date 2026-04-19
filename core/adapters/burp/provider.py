"""Provider-facing Burp MCP adapter with capability policy gating.

This provider intentionally exposes only an initial safe subset and does not
contain orchestration logic.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from core.adapters.burp.capabilities import SAFE_EXPOSED_TOOLS
from core.adapters.burp.client import BurpMcpClient
from core.adapters.burp.config import BurpMcpConfig
from core.adapters.burp.exceptions import BurpUnsupportedCapabilityError
from core.adapters.burp.models import BurpProviderState, BurpSessionState, NormalizedBurpHttpRecord
from core.adapters.burp.normalizers import normalize_http_history_records, normalize_http_send_response
from core.adapters.burp.policy import BurpCapabilityPolicy

LOGGER = logging.getLogger(__name__)


class BurpMcpProvider:
    """Safe-by-default Burp provider API for ReconForge integration."""

    def __init__(self, config: BurpMcpConfig | None = None, policy: BurpCapabilityPolicy | None = None):
        self.config = config or BurpMcpConfig()
        self.policy = policy or BurpCapabilityPolicy()
        self.client = BurpMcpClient(self.config, self.policy)
        self._state = BurpProviderState(session=BurpSessionState(base_url=self.config.base_url))

    def start(self) -> BurpProviderState:
        self.client.connect()
        capabilities = self.client.discover_capabilities()
        enabled = [c.name for c in capabilities if c.enabled]
        disabled = [c.name for c in capabilities if not c.enabled]
        self._state = BurpProviderState(
            session=self.client.connection.state,
            discovered_tools=capabilities,
            enabled_tools=enabled,
            disabled_tools=disabled,
        )
        LOGGER.info(json.dumps({"event": "burp_provider_started", "enabled_tools": enabled}))
        return self.state

    def stop(self) -> None:
        self.client.close()

    @property
    def state(self) -> BurpProviderState:
        return self._state

    # ---- Initial safe API surface ----

    def send_http1_request(self, arguments: Dict[str, Any]) -> List[NormalizedBurpHttpRecord]:
        return self._execute_and_normalize("send_http1_request", arguments)

    def send_http2_request(self, arguments: Dict[str, Any]) -> List[NormalizedBurpHttpRecord]:
        return self._execute_and_normalize("send_http2_request", arguments)

    def get_proxy_http_history(self, arguments: Dict[str, Any]) -> List[NormalizedBurpHttpRecord]:
        return self._execute_and_normalize("get_proxy_http_history", arguments)

    def get_proxy_http_history_regex(self, arguments: Dict[str, Any]) -> List[NormalizedBurpHttpRecord]:
        return self._execute_and_normalize("get_proxy_http_history_regex", arguments)

    def _execute_and_normalize(self, tool_name: str, arguments: Dict[str, Any]) -> List[NormalizedBurpHttpRecord]:
        self._require_allowed(tool_name)
        raw = self.client.call_tool(tool_name, arguments)
        evidence = f"burp:{tool_name}"

        if tool_name in {"send_http1_request", "send_http2_request"}:
            return normalize_http_send_response(raw, tool_name=tool_name, evidence_source=evidence)
        return normalize_http_history_records(raw, tool_name=tool_name, evidence_source=evidence)

    def _require_allowed(self, tool_name: str) -> None:
        if not self.policy.is_allowed(tool_name):
            reason = self.policy.deny_reason(tool_name)
            LOGGER.warning(json.dumps({"event": "burp_policy_denied", "tool": tool_name, "reason": reason}))
            raise BurpUnsupportedCapabilityError(f"Tool '{tool_name}' denied: {reason}")
        if not self.client.has_capability(tool_name):
            raise BurpUnsupportedCapabilityError(
                f"Tool '{tool_name}' is not available in discovered capabilities or disabled by server"
            )
