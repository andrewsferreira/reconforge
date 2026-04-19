"""Entrypoint for vulnerability classification and correlation execution."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from core.adapters.burp.config import BurpMcpConfig
from core.adapters.burp.provider import BurpMcpProvider
from reconforge.collectors.http_collector import HttpCollector
from reconforge.intelligence.engine import ValidationLoopResult, VulnerabilityIntelligenceEngine


@dataclass
class IntelligenceRunConfig:
    mcp_url: str
    endpoints: list[str]
    allow_domains: tuple[str, ...]
    deny_domains: tuple[str, ...]
    allow_subdomains: bool = True


def run_vulnerability_intelligence(config: IntelligenceRunConfig) -> ValidationLoopResult:
    provider = BurpMcpProvider(
        config=BurpMcpConfig(
            base_url=config.mcp_url,
            scope_allowed_domains=config.allow_domains,
            scope_denied_domains=config.deny_domains,
            scope_allow_subdomains=config.allow_subdomains,
        )
    )
    collector = HttpCollector(provider)
    engine = VulnerabilityIntelligenceEngine(collector)

    provider.start()
    try:
        return engine.run_validation_loop(config.endpoints)
    finally:
        provider.stop()


def save_validation_result(result: ValidationLoopResult, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return path
