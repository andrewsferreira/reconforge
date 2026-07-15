"""Capability policy gating for Burp MCP provider."""

from __future__ import annotations

from dataclasses import dataclass, field

from core.adapters.burp.capabilities import SAFE_EXPOSED_TOOLS

_DEFAULT_BLOCKED_KEYWORDS = (
    "config",
    "intercept",
    "editor",
    "task",
    "intruder",
    "scanner",
    "project",
    "ui",
)


@dataclass(frozen=True)
class BurpCapabilityPolicy:
    enabled_tools: set[str] = field(default_factory=lambda: set(SAFE_EXPOSED_TOOLS))
    blocked_keywords: tuple[str, ...] = _DEFAULT_BLOCKED_KEYWORDS

    def is_allowed(self, tool_name: str) -> bool:
        name = tool_name.strip()
        if not name:
            return False
        if name not in self.enabled_tools:
            return False
        lowered = name.lower()
        return not any(k in lowered for k in self.blocked_keywords)

    def deny_reason(self, tool_name: str) -> str:
        if tool_name not in self.enabled_tools:
            return "tool not in initial safe exposure allowlist"
        lowered = tool_name.lower()
        if any(k in lowered for k in self.blocked_keywords):
            return "tool category blocked by default policy"
        return "allowed"
