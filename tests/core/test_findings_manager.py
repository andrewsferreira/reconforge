"""Tests for core.findings_manager – Finding, FindingsManager, _clamp_severity.

Phase 8-I: core/findings_manager.py had zero test coverage prior to this.
"""

import pytest

from core.findings_manager import (
    Finding,
    FindingsManager,
    _clamp_severity,
    _CONFIDENCE_SEVERITY_CAP,
    _SEVERITY_RANK,
)


# ── _clamp_severity: full confidence x severity matrix ──────────────

@pytest.mark.parametrize("confidence,severity,expected", [
    # confirmed/high: no cap, any severity passes through unchanged
    ("confirmed", "critical", "critical"),
    ("confirmed", "high", "high"),
    ("confirmed", "medium", "medium"),
    ("confirmed", "low", "low"),
    ("confirmed", "info", "info"),
    ("high", "critical", "critical"),
    ("high", "info", "info"),
    # medium: capped at high
    ("medium", "critical", "high"),
    ("medium", "high", "high"),
    ("medium", "medium", "medium"),
    ("medium", "low", "low"),
    ("medium", "info", "info"),
    # low: capped at medium
    ("low", "critical", "medium"),
    ("low", "high", "medium"),
    ("low", "medium", "medium"),
    ("low", "low", "low"),
    ("low", "info", "info"),
    # heuristic: capped at low
    ("heuristic", "critical", "low"),
    ("heuristic", "high", "low"),
    ("heuristic", "medium", "low"),
    ("heuristic", "low", "low"),
    ("heuristic", "info", "info"),
])
def test_clamp_severity_full_matrix(confidence, severity, expected):
    assert _clamp_severity(severity, confidence) == expected


def test_confidence_severity_cap_covers_all_valid_confidences():
    assert set(_CONFIDENCE_SEVERITY_CAP) == FindingsManager.VALID_CONFIDENCES


def test_severity_rank_covers_all_valid_severities():
    assert set(_SEVERITY_RANK) == FindingsManager.VALID_SEVERITIES


# ── FindingsManager.add(): validation and clamping ──────────────────

def test_add_returns_finding_with_expected_fields():
    mgr = FindingsManager()
    f = mgr.add(
        finding_type="vulnerability", severity="high", confidence="confirmed",
        target="10.10.10.1", module="network", description="Test finding",
        evidence="proof", recommendation="fix it",
    )
    assert isinstance(f, Finding)
    assert f.severity == "high"
    assert f.confidence == "confirmed"
    assert f.target == "10.10.10.1"
    assert f.module == "network"
    assert f.description == "Test finding"
    assert f.id  # auto-generated


def test_add_clamps_severity_in_strict_mode():
    mgr = FindingsManager(strict=True)
    f = mgr.add(
        finding_type="vulnerability", severity="critical", confidence="heuristic",
        target="x", module="web", description="Weak signal",
    )
    assert f.severity == "low"
    assert "[severity clamped: critical→low]" in f.description
    assert mgr.clamped_count == 1


def test_add_does_not_clamp_in_non_strict_mode():
    mgr = FindingsManager(strict=False)
    f = mgr.add(
        finding_type="vulnerability", severity="critical", confidence="heuristic",
        target="x", module="web", description="Weak signal",
    )
    assert f.severity == "critical"
    assert mgr.clamped_count == 0


def test_add_no_clamp_note_when_severity_already_within_cap():
    mgr = FindingsManager()
    f = mgr.add(
        finding_type="vulnerability", severity="low", confidence="heuristic",
        target="x", module="web", description="Fine as-is",
    )
    assert f.severity == "low"
    assert "clamped" not in f.description
    assert mgr.clamped_count == 0


def test_add_normalizes_case_and_whitespace():
    mgr = FindingsManager()
    f = mgr.add(
        finding_type="x", severity="  HIGH  ", confidence="  Confirmed  ",
        target="x", module="x", description="x",
    )
    assert f.severity == "high"
    assert f.confidence == "confirmed"


def test_add_unknown_severity_defaults_to_info_with_warning():
    mgr = FindingsManager()
    with pytest.warns(UserWarning, match="Unknown severity"):
        f = mgr.add(
            finding_type="x", severity="apocalyptic", confidence="confirmed",
            target="x", module="x", description="x",
        )
    assert f.severity == "info"


def test_add_unknown_confidence_defaults_to_low_with_warning():
    mgr = FindingsManager()
    with pytest.warns(UserWarning, match="Unknown confidence"):
        f = mgr.add(
            finding_type="x", severity="high", confidence="pretty_sure",
            target="x", module="x", description="x",
        )
    assert f.confidence == "low"


def test_add_accepts_confidence_reason():
    mgr = FindingsManager()
    f = mgr.add(
        finding_type="vulnerability", severity="high", confidence="high",
        target="x", module="x", description="x",
        confidence_reason="direct tool output, deterministic match",
    )
    assert f.confidence_reason == "direct tool output, deterministic match"


def test_add_confidence_reason_defaults_to_empty_string():
    mgr = FindingsManager()
    f = mgr.add(
        finding_type="x", severity="info", confidence="medium",
        target="x", module="x", description="x",
    )
    assert f.confidence_reason == ""


# ── Getters / aggregates ─────────────────────────────────────────────

def _populate(mgr: FindingsManager):
    mgr.add(finding_type="a", severity="critical", confidence="confirmed",
             target="t1", module="network", description="d1")
    mgr.add(finding_type="b", severity="medium", confidence="medium",
             target="t2", module="web", description="d2")
    mgr.add(finding_type="c", severity="low", confidence="heuristic",
             target="t3", module="web", description="d3")


def test_get_all_sorted_by_severity():
    mgr = FindingsManager()
    _populate(mgr)
    severities = [f.severity for f in mgr.get_all()]
    assert severities == ["critical", "medium", "low"]


def test_get_by_severity():
    mgr = FindingsManager()
    _populate(mgr)
    assert len(mgr.get_by_severity("critical")) == 1
    assert len(mgr.get_by_severity("info")) == 0


def test_get_by_confidence():
    mgr = FindingsManager()
    _populate(mgr)
    assert len(mgr.get_by_confidence("heuristic")) == 1
    assert len(mgr.get_by_confidence("confirmed")) == 1


def test_get_by_module():
    mgr = FindingsManager()
    _populate(mgr)
    assert len(mgr.get_by_module("web")) == 2
    assert len(mgr.get_by_module("network")) == 1


def test_get_heuristic_findings():
    mgr = FindingsManager()
    _populate(mgr)
    heuristic = mgr.get_heuristic_findings()
    assert len(heuristic) == 1
    assert heuristic[0].confidence == "heuristic"


def test_count_by_severity():
    mgr = FindingsManager()
    _populate(mgr)
    counts = mgr.count_by_severity()
    assert counts == {"critical": 1, "medium": 1, "low": 1}


def test_count_by_confidence():
    mgr = FindingsManager()
    _populate(mgr)
    counts = mgr.count_by_confidence()
    assert counts == {"confirmed": 1, "medium": 1, "heuristic": 1}


# ── Serialization ─────────────────────────────────────────────────────

def test_to_json_round_trips_findings():
    import json
    mgr = FindingsManager()
    _populate(mgr)
    data = json.loads(mgr.to_json())
    assert len(data) == 3
    assert data[0]["severity"] == "critical"


def test_to_markdown_includes_heuristic_findings_section():
    mgr = FindingsManager()
    _populate(mgr)
    md = mgr.to_markdown()
    assert "Heuristic Findings" in md
    assert "d3" in md  # the heuristic finding's description appears


def test_to_markdown_omits_heuristic_section_when_none_present():
    mgr = FindingsManager()
    mgr.add(finding_type="a", severity="high", confidence="confirmed",
             target="t", module="m", description="d")
    md = mgr.to_markdown()
    assert "Heuristic Findings" not in md


def test_to_markdown_shows_confidence_reason_when_present():
    mgr = FindingsManager()
    mgr.add(finding_type="a", severity="high", confidence="high",
             target="t", module="m", description="d",
             confidence_reason="explicit reasoning here")
    md = mgr.to_markdown()
    assert "explicit reasoning here" in md


def test_to_markdown_omits_confidence_reason_when_absent():
    mgr = FindingsManager()
    mgr.add(finding_type="a", severity="high", confidence="high",
             target="t", module="m", description="d")
    md = mgr.to_markdown()
    assert "Confidence Reason" not in md


def test_to_markdown_shows_clamped_count_note():
    mgr = FindingsManager()
    mgr.add(finding_type="a", severity="critical", confidence="heuristic",
             target="t", module="m", description="d")
    md = mgr.to_markdown()
    assert "Severity Clamped" in md


def test_save_json_and_markdown(tmp_path):
    mgr = FindingsManager()
    _populate(mgr)

    json_path = tmp_path / "findings.json"
    md_path = tmp_path / "findings.md"
    mgr.save_json(json_path)
    mgr.save_markdown(md_path)

    assert json_path.is_file()
    assert md_path.is_file()
    assert "Heuristic Findings" in md_path.read_text()
