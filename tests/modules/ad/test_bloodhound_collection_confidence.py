"""Phase 8-B: BloodhoundCollectionPhase's Domain Admin attack-path finding
must not claim confidence="confirmed" — a BloodHound graph-traversal
inference is not an exploited/verified fact, per core/findings_manager.py's
own confidence definitions.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

from core.findings_manager import FindingsManager
from modules.ad.analyzers.base import AnalysisResult
from modules.ad.phases.bloodhound_collection import BloodhoundCollectionPhase


def _make_phase() -> BloodhoundCollectionPhase:
    phase = BloodhoundCollectionPhase.__new__(BloodhoundCollectionPhase)
    phase.PHASE_NAME = "bloodhound_collection"
    phase.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None)
    phase.notes = SimpleNamespace(
        add_phase_start=lambda *a, **k: None,
        add_phase_end=lambda *a, **k: None,
    )
    phase.findings = FindingsManager()
    phase.workflow = SimpleNamespace(
        add_step=lambda **k: None,
        record_result=lambda *a, **k: None,
        add_attack_path=lambda **k: None,
        suggest_next=lambda **k: None,
    )

    _empty_build_result = SimpleNamespace(chains=[], suggestions=[])
    _builder_stub = SimpleNamespace(build=lambda *a, **k: _empty_build_result)
    phase.kerberoast_builder = _builder_stub
    phase.asrep_builder = _builder_stub
    phase.acl_builder = _builder_stub

    phase.bh_collector = SimpleNamespace(
        collect=lambda **kwargs: SimpleNamespace(
            success=True, errors=[],
            data={
                "collection_method": "bloodhound-python",
                "users_collected": 1, "groups_collected": 1,
                "computers_collected": 1, "sessions_collected": 0,
                "domains_collected": 1,
                "users": [], "groups": [], "computers": [],
            },
        )
    )
    phase.privilege_analyzer = SimpleNamespace(
        analyze=lambda *a, **k: AnalysisResult(analyzer="privilege")
    )
    # Bypass the real graph-traversal algorithm — feed a canned critical path.
    phase._identify_da_paths = MagicMock(return_value=[
        {"type": "ACL", "source": "alice", "target": "Domain Admins",
         "risk": "critical", "steps": ["alice has GenericAll on Domain Admins"]},
    ])

    return phase


def test_da_path_finding_uses_high_not_confirmed_confidence():
    phase = _make_phase()

    phase.run(target="10.10.10.1", domain="corp.local",
              username="alice", password="pass")

    findings = phase.findings.get_all()
    da_findings = [f for f in findings if "attack paths to Domain Admin" in f.description]
    assert len(da_findings) == 1
    assert da_findings[0].confidence == "high"
    assert da_findings[0].confidence != "confirmed"
    assert da_findings[0].confidence_reason
    assert da_findings[0].severity == "critical"  # "high" confidence still allows critical
