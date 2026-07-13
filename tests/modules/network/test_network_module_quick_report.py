"""Phase 8-F: quick_report.md must surface a visible note when findings
were severity-clamped, since the "Critical & High Findings" section only
shows POST-clamp severity — a finding that started critical but got
downgraded to medium/low due to weak confidence previously vanished from
the quick report's headline section with zero operator-facing signal.
"""

from types import SimpleNamespace

from core.findings_manager import FindingsManager
from modules.network.network_module import NetworkModule


def _make_module(tmp_path) -> NetworkModule:
    module = NetworkModule.__new__(NetworkModule)
    module.target_str = "10.10.10.1"
    module.opsec_mode = "normal"
    module.findings_mgr = FindingsManager()
    module.loot = SimpleNamespace(summary=lambda: {})
    module.workflow = SimpleNamespace(attack_paths=[], get_suggestions=lambda: [])
    module.output = SimpleNamespace(report_file=lambda *_a, **_k: tmp_path / "quick_report.md")
    return module


def test_quick_report_shows_clamped_note_when_findings_downgraded(tmp_path):
    module = _make_module(tmp_path)
    # heuristic confidence caps critical -> low, triggering a clamp
    module.findings_mgr.add(
        finding_type="vulnerability", severity="critical", confidence="heuristic",
        target="10.10.10.1", module="network", description="weak pattern match",
    )

    module._generate_quick_report({})

    report = (tmp_path / "quick_report.md").read_text()
    assert "severity downgraded" in report
    assert "1 finding(s)" in report


def test_quick_report_omits_clamped_note_when_no_clamping_occurred(tmp_path):
    module = _make_module(tmp_path)
    module.findings_mgr.add(
        finding_type="vulnerability", severity="high", confidence="confirmed",
        target="10.10.10.1", module="network", description="verified issue",
    )

    module._generate_quick_report({})

    report = (tmp_path / "quick_report.md").read_text()
    assert "severity downgraded" not in report
