"""Provider-facing Burp MCP adapter with capability policy gating.

This provider intentionally exposes only an initial safe subset and does not
contain orchestration logic.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from core.adapters.burp.client import BurpMcpClient
from core.adapters.burp.config import BurpMcpConfig
from core.adapters.burp.exceptions import (
    BurpMalformedTargetError,
    BurpOutOfScopeError,
    BurpUnsupportedCapabilityError,
)
from core.adapters.burp.models import BurpProviderState, BurpSessionState, NormalizedBurpHttpRecord
from core.adapters.burp.normalizers import (
    normalize_http_history_records,
    normalize_http_send_response,
)
from core.adapters.burp.policy import BurpCapabilityPolicy
from core.policy.target_scope import DomainScopeDecision, DomainScopePolicy, DomainScopeValidator

LOGGER = logging.getLogger(__name__)


class BurpMcpProvider:
    """Safe-by-default Burp provider API for ReconForge integration."""

    def __init__(
        self,
        config: BurpMcpConfig | None = None,
        policy: BurpCapabilityPolicy | None = None,
        scope_policy: DomainScopePolicy | None = None,
        scope_validator: DomainScopeValidator | None = None,
    ):
        self.config = config or BurpMcpConfig()
        self.policy = policy or BurpCapabilityPolicy()
        self.scope_policy = scope_policy or DomainScopePolicy(
            allowed_domains=self.config.scope_allowed_domains,
            denied_domains=self.config.scope_denied_domains,
            allow_subdomains=self.config.scope_allow_subdomains,
        )
        self.scope_validator = scope_validator or DomainScopeValidator()
        self.client = BurpMcpClient(self.config, self.policy)
        self._state = BurpProviderState(session=BurpSessionState(base_url=self.config.base_url))
        self._last_scope_decision = DomainScopeDecision(
            target="",
            host="",
            normalized_host="",
            in_scope=False,
            decision="blocked",
            matched_rule="",
            reason="not_evaluated",
            source_policy_type=self.scope_validator.POLICY_TYPE,
            subdomain_match_used=False,
        )

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

    @property
    def last_scope_decision(self) -> DomainScopeDecision:
        return self._last_scope_decision

    # ---- Initial safe API surface ----

    def send_http1_request(self, arguments: dict[str, Any]) -> list[NormalizedBurpHttpRecord]:
        self._enforce_request_scope(arguments)
        return self._execute_and_normalize("send_http1_request", arguments)

    def send_http2_request(self, arguments: dict[str, Any]) -> list[NormalizedBurpHttpRecord]:
        self._enforce_request_scope(arguments)
        return self._execute_and_normalize("send_http2_request", arguments)

    def get_proxy_http_history(self, arguments: dict[str, Any]) -> list[NormalizedBurpHttpRecord]:
        return self._execute_and_normalize("get_proxy_http_history", arguments)

    def get_proxy_http_history_regex(self, arguments: dict[str, Any]) -> list[NormalizedBurpHttpRecord]:
        return self._execute_and_normalize("get_proxy_http_history_regex", arguments)

    def _execute_and_normalize(self, tool_name: str, arguments: dict[str, Any]) -> list[NormalizedBurpHttpRecord]:
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

    def _enforce_request_scope(self, arguments: dict[str, Any]) -> None:
        target = _extract_target(arguments)
        self._last_scope_decision = self.scope_validator.validate_target(target, self.scope_policy)

        LOGGER.info(
            json.dumps(
                {
                    "event": "burp_request_scope_evaluated",
                    **self._last_scope_decision.to_dict(),
                }
            )
        )

        if self._last_scope_decision.in_scope:
            return

        if self._last_scope_decision.reason == "malformed_target":
            raise BurpMalformedTargetError(
                f"Blocked Burp request: malformed target '{target}'. decision={self._last_scope_decision.to_dict()}"
            )
        raise BurpOutOfScopeError(
            f"Blocked Burp request: target '{target}' out of scope. decision={self._last_scope_decision.to_dict()}"
        )


def _extract_target(arguments: dict[str, Any]) -> str:
    for key in ("url", "requestUrl", "target"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""
