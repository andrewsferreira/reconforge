"""Capability discovery and classification for Burp MCP tools."""

from __future__ import annotations

from typing import Dict, Iterable, List

from core.adapters.burp.models import BurpCapability


SAFE_EXPOSED_TOOLS: tuple[str, ...] = (
    "send_http1_request",
    "send_http2_request",
    "get_proxy_http_history",
    "get_proxy_http_history_regex",
)


def classify_capabilities(raw_tools: Iterable[dict], enabled_tools: set[str]) -> List[BurpCapability]:
    capabilities: List[BurpCapability] = []
    for item in raw_tools:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        description = str(item.get("description", "")).strip()
        schema = item.get("inputSchema") if isinstance(item.get("inputSchema"), dict) else {}
        enabled = name in enabled_tools
        reason = "enabled by burp capability policy" if enabled else "disabled by default policy"
        capabilities.append(
            BurpCapability(
                name=name,
                description=description,
                input_schema=schema,
                enabled=enabled,
                reason=reason,
            )
        )
    return capabilities


def build_capability_map(capabilities: Iterable[BurpCapability]) -> Dict[str, BurpCapability]:
    return {cap.name: cap for cap in capabilities}
