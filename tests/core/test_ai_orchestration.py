"""Tests for the rule-based correlation/prioritization layer in
core/ai_orchestration.py — see docs/AI_ORCHESTRATION_ARCHITECTURE.md's
Phase 30 status note: this is deterministic (fixed keyword rules, hand-
written confidence literals, a linear weighted score), not ML/LLM, so
every behavior here is exactly reproducible and worth pinning down with
precise value assertions rather than loose shape checks alone.
"""

from core.ai_orchestration import AIOrchestrationLayer, CorrelatedSignal


def test_risk_score_uses_the_documented_weighted_formula():
    """0.35*severity + 0.30*exploit_likelihood + 0.20*reachability +
    0.15*asset_criticality, scaled by the confidence multiplier."""
    sig = CorrelatedSignal(
        source_module="test", signal_type="x", target="t", evidence="e",
        severity="critical", confidence="confirmed",
        exploit_likelihood=1.0, reachability=1.0, asset_criticality=1.0,
    )
    assert sig.risk_score() == 100.0

    default_sig = CorrelatedSignal(
        source_module="test", signal_type="x", target="t", evidence="e",
    )
    # severity="info" (1/10), confidence="low" (0.5), likelihood/reachability
    # default 0.1, criticality default 0.5:
    # (0.35*0.1 + 0.30*0.1 + 0.20*0.1 + 0.15*0.5) * 0.5 * 100 == 8.0
    assert default_sig.risk_score() == 8.0


def test_ingest_network_boosts_risk_for_known_high_risk_ports():
    engine = AIOrchestrationLayer()
    engine.ingest_nmap_scan({
        "10.10.10.30": {
            "open_ports": [
                {"port": 445, "service": "microsoft-ds", "version": ""},
                {"port": 22, "service": "ssh", "version": ""},
            ]
        }
    })
    by_target = {s.target: s for s in engine.signals}
    assert by_target["10.10.10.30:445"].exploit_likelihood == 0.6
    assert by_target["10.10.10.30:445"].severity == "medium"
    assert by_target["10.10.10.30:22"].exploit_likelihood == 0.35
    assert by_target["10.10.10.30:22"].severity == "low"


def test_ingest_network_applies_cve_hints_for_known_banners():
    """A banner matching _BANNER_CVE_HINTS bumps exploit_likelihood by
    0.25 (capped at 0.95), escalates severity to "high", and attaches
    the reference."""
    engine = AIOrchestrationLayer()
    engine.ingest_nmap_scan({
        "10.10.10.40": {
            "open_ports": [{"port": 80, "service": "http", "version": "Apache 2.4.49"}]
        }
    })
    sig = next(s for s in engine.signals if s.target == "10.10.10.40:80")
    assert sig.severity == "high"
    assert sig.exploit_likelihood == 0.6  # 0.35 base (port 80 not high-risk) + 0.25
    assert "CVE-2021-41773" in sig.references


def test_ingest_web_maps_finding_fields_onto_a_signal():
    engine = AIOrchestrationLayer()
    created = engine._ingest_web({
        "target": "https://example.com/login",
        "findings": [{
            "type": "auth_bypass_candidate",
            "description": "Weak session cookie",
            "severity": "high",
            "confidence": "medium",
            "references": ["https://example.com/ref"],
        }],
    })
    assert len(created) == 1
    sig = created[0]
    assert sig.source_module == "web"
    assert sig.severity == "high"
    assert sig.confidence == "medium"
    assert sig.evidence == "Weak session cookie"
    assert sig.references == ["https://example.com/ref"]


def test_ingest_api_tags_and_boosts_likelihood_relative_to_web():
    engine = AIOrchestrationLayer()
    web_created = engine._ingest_web({
        "target": "https://api.example.com",
        "findings": [{"type": "x", "description": "y", "severity": "high", "confidence": "medium"}],
    })
    api_created = engine._ingest_api({
        "target": "https://api.example.com",
        "findings": [{"type": "x", "description": "y", "severity": "high", "confidence": "medium"}],
    })
    assert "api" in api_created[0].tags
    assert api_created[0].source_module == "api"
    assert api_created[0].exploit_likelihood == round(web_created[0].exploit_likelihood + 0.1, 10)


def test_ingest_ad_creates_a_domain_surface_signal():
    engine = AIOrchestrationLayer()
    created = engine._ingest_ad({"domain": "corp.local"})
    assert len(created) == 1
    assert created[0].source_module == "ad"
    assert created[0].signal_type == "domain_surface"
    assert created[0].target == "corp.local"


def test_ingest_ad_with_no_domain_creates_nothing():
    engine = AIOrchestrationLayer()
    assert engine._ingest_ad({}) == []


def test_top_attack_paths_excludes_low_risk_signals():
    """top_attack_paths() only surfaces signals scoring >= 30."""
    engine = AIOrchestrationLayer()
    engine.signals.append(CorrelatedSignal(
        source_module="test", signal_type="low_risk", target="t1", evidence="e",
        severity="info", confidence="low",
    ))  # risk_score == 8.0, below the 30 cutoff
    engine.signals.append(CorrelatedSignal(
        source_module="test", signal_type="high_risk", target="t2", evidence="e",
        severity="critical", confidence="confirmed",
        exploit_likelihood=1.0, reachability=1.0, asset_criticality=1.0,
    ))  # risk_score == 100.0
    paths = engine.top_attack_paths(limit=5)
    targets = {p["target"] for p in paths}
    assert "t2" in targets
    assert "t1" not in targets


def test_decide_next_actions_recommends_modules_from_seen_services():
    engine = AIOrchestrationLayer()
    engine.ingest_nmap_scan({
        "10.10.10.50": {"open_ports": [{"port": 389, "service": "ldap", "version": ""}]}
    })
    recs = engine.decide_next_actions(already_planned=set())
    by_module = {r["module"]: r for r in recs}
    assert by_module["ad"]["confidence"] == 0.9
    assert "web" not in by_module  # no http/https service seen


def test_decide_next_actions_skips_already_planned_service_modules():
    engine = AIOrchestrationLayer()
    engine.ingest_nmap_scan({
        "10.10.10.60": {"open_ports": [{"port": 80, "service": "http", "version": ""}]}
    })
    recs = engine.decide_next_actions(already_planned={"web", "api"})
    modules = {r["module"] for r in recs}
    assert "web" not in modules
    assert "api" not in modules


def test_generate_ai_report_has_the_documented_sections():
    engine = AIOrchestrationLayer()
    engine.ingest_nmap_scan({
        "10.10.10.70": {"open_ports": [{"port": 445, "service": "microsoft-ds", "version": "Samba 3.6"}]}
    })
    report = engine.generate_ai_report()
    assert set(report.keys()) == {
        "executive_summary", "technical_findings", "attack_narrative",
        "recommendations", "triage",
    }
    assert report["executive_summary"]["signals"] == len(engine.signals)
    assert isinstance(report["technical_findings"], list)
    assert isinstance(report["triage"], list)


def test_ingest_nmap_scan_creates_graph_and_signals():
    engine = AIOrchestrationLayer()
    engine.ingest_nmap_scan({
        "10.10.10.10": {
            "open_ports": [
                {"port": 80, "service": "http", "version": "Apache 2.4.49"},
                {"port": 445, "service": "microsoft-ds", "version": "Samba 3.6"},
            ]
        }
    })

    snapshot = engine.build_context_snapshot()
    assert snapshot["signals_total"] >= 2
    assert any(n["type"] == "service" for n in snapshot["graph"]["nodes"])
    assert engine.top_attack_paths(limit=1)


def test_decision_engine_suggests_web_and_api_for_http_services():
    engine = AIOrchestrationLayer()
    engine.ingest_nmap_scan({
        "10.10.10.20": {"open_ports": [{"port": 80, "service": "http", "version": "nginx"}]}
    })

    recs = engine.decide_next_actions(already_planned={"network"})
    modules = {r["module"] for r in recs}
    assert "web" in modules
    assert "api" in modules
