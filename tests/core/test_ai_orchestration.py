"""Tests for AI orchestration layer."""

from core.ai_orchestration import AIOrchestrationLayer


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
