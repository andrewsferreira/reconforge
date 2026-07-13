"""Phase 11-C: DelegationDiscoveryPhase.run() must not silently proceed
through loot/analysis/attack-path steps on empty data when the collector
couldn't actually complete any query -- that produces the same "looks like
a clean scan" false signal the hardcoded success=True bug caused, just one
layer up. Must surface a finding and return with success=False instead.
"""

from types import SimpleNamespace

from core.findings_manager import FindingsManager
from modules.ad.phases.delegation_discovery import DelegationDiscoveryPhase


def _make_phase(collector_success: bool, errors=None) -> DelegationDiscoveryPhase:
    phase = DelegationDiscoveryPhase.__new__(DelegationDiscoveryPhase)
    phase.PHASE_NAME = "delegation_discovery"
    phase.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None)
    phase.notes = SimpleNamespace(
        add_phase_start=lambda *a, **k: None,
        add_phase_end=lambda *a, **k: None,
    )
    phase.findings = FindingsManager()
    phase.loot = SimpleNamespace(add=lambda **k: None)
    phase.workflow = SimpleNamespace(add_attack_path=lambda **k: None, suggest_next=lambda **k: None)
    phase.misconfig_analyzer = SimpleNamespace(
        analyze=lambda *a, **k: SimpleNamespace(findings=[])
    )
    phase.delegation_path_builder = SimpleNamespace(
        build=lambda *a, **k: SimpleNamespace(chains=[], suggestions=[])
    )
    phase.delegation_collector = SimpleNamespace(
        collect=lambda **k: SimpleNamespace(
            success=collector_success, errors=errors or [], data={},
        )
    )
    return phase


def test_collector_failure_returns_success_false():
    phase = _make_phase(collector_success=False, errors=["ldapsearch unavailable"])

    results = phase.run(target="10.10.10.1", domain="corp.local",
                         username="alice", password="pass")

    assert results["success"] is False


def test_collector_failure_surfaces_a_finding_not_silent():
    phase = _make_phase(collector_success=False, errors=["ldapsearch unavailable"])

    phase.run(target="10.10.10.1", domain="corp.local",
              username="alice", password="pass")

    findings = phase.findings.get_all()
    assert len(findings) == 1
    assert "incomplete" in findings[0].description.lower()
    assert "ldapsearch unavailable" in findings[0].evidence


def test_collector_success_reaches_final_success_true():
    phase = _make_phase(collector_success=True)
    phase.delegation_collector = SimpleNamespace(
        collect=lambda **k: SimpleNamespace(
            success=True, errors=[],
            data={"unconstrained": [], "constrained": [], "rbcd": [], "machine_account_quota": -1},
        )
    )

    results = phase.run(target="10.10.10.1", domain="corp.local",
                         username="alice", password="pass")

    assert results["success"] is True
    assert phase.findings.get_all() == []
