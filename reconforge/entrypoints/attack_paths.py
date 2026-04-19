"""Entrypoint for generating validated attack paths from intelligence output."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from core.adapters.burp.config import BurpMcpConfig
from core.adapters.burp.provider import BurpMcpProvider
from reconforge.attack_paths.engine import AttackPathGenerationEngine, AttackPathReport
from reconforge.collectors.http_collector import HttpCollector
from reconforge.intelligence.engine import VulnerabilityIntelligenceEngine


@dataclass
class AttackPathRunConfig:
    mcp_url: str
    endpoints: list[str]
    allow_domains: tuple[str, ...]
    deny_domains: tuple[str, ...]
    allow_subdomains: bool = True
    refinement_rounds: int = 1


def run_attack_path_generation(config: AttackPathRunConfig) -> AttackPathReport:
    provider = BurpMcpProvider(
        config=BurpMcpConfig(
            base_url=config.mcp_url,
            scope_allowed_domains=config.allow_domains,
            scope_denied_domains=config.deny_domains,
            scope_allow_subdomains=config.allow_subdomains,
        )
    )
    collector = HttpCollector(provider)
    vuln_engine = VulnerabilityIntelligenceEngine(collector)
    path_engine = AttackPathGenerationEngine(collector)

    provider.start()
    try:
        intelligence = vuln_engine.run(config.endpoints, correlation_enabled=True)
        return path_engine.run(intelligence, refinement_rounds=config.refinement_rounds)
    finally:
        provider.stop()


def save_attack_path_report(report: AttackPathReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return path
