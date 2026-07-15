"""Tests for core.engagement – EngagementManager."""

import json
from unittest.mock import MagicMock

import pytest

from core.engagement import EngagementManager
from core.exceptions import EngagementError

# ── lifecycle ───────────────────────────────────────────────────

def test_initial_status():
    em = EngagementManager(client="Acme", operator="alice")
    assert em.status == "planning"


def test_start():
    em = EngagementManager(client="Acme", operator="alice")
    em.start()
    assert em.status == "active"


def test_pause_and_resume():
    em = EngagementManager(client="Acme", operator="alice")
    em.start()
    em.pause()
    assert em.status == "paused"
    em.resume()
    assert em.status == "active"


def test_complete():
    em = EngagementManager(client="Acme", operator="alice")
    em.start()
    em.complete()
    assert em.status == "completed"


def test_cancel():
    em = EngagementManager(client="Acme", operator="alice")
    em.start()
    em.cancel()
    assert em.status == "cancelled"


def test_cannot_cancel_a_completed_engagement():
    """Phase 13-B regression: cancel() was the only lifecycle method with
    no state guard — calling it on a completed engagement silently
    overwrote end_time and appended a duplicate cancellation entry."""
    em = EngagementManager(client="Acme", operator="alice")
    em.start()
    em.complete()

    with pytest.raises(EngagementError):
        em.cancel()

    assert em.status == "completed"


def test_cannot_cancel_an_already_cancelled_engagement():
    em = EngagementManager(client="Acme", operator="alice")
    em.start()
    em.cancel()

    with pytest.raises(EngagementError):
        em.cancel()


def test_invalid_transition():
    em = EngagementManager(client="Acme", operator="alice")
    # Cannot complete from planning (must start first)
    with pytest.raises(EngagementError):
        em.complete()


def test_cannot_resume_when_active():
    em = EngagementManager(client="Acme", operator="alice")
    em.start()
    with pytest.raises(EngagementError):
        em.resume()


# ── timeline ────────────────────────────────────────────────────

def test_timeline_records():
    em = EngagementManager(client="Acme", operator="alice")
    em.start()
    em.record_action(module="network", action="port_scan", detail="TCP SYN")
    timeline = em.get_timeline()
    assert len(timeline) >= 2  # start + action


def test_record_module_result():
    em = EngagementManager(client="Acme", operator="alice")
    em.start()
    em.record_module_result("network", {"phases": {"discovery": {}}})
    assert "network" in em.modules_run


# ── findings / loot summaries ───────────────────────────────────

def test_update_findings_summary():
    em = EngagementManager(client="Acme", operator="alice")
    fm = MagicMock()
    fm.count_by_severity.return_value = {"critical": 1, "high": 2}
    em.update_findings_summary(fm)
    assert em.findings_summary["critical"] == 1


def test_update_loot_summary():
    em = EngagementManager(client="Acme", operator="alice")
    lm = MagicMock()
    lm.summary.return_value = {"credential": 5}
    em.update_loot_summary(lm)
    assert em.loot_summary["credential"] == 5


# ── serialisation ───────────────────────────────────────────────

def test_to_dict():
    em = EngagementManager(client="Acme", operator="alice")
    d = em.to_dict()
    assert d["meta"]["client"] == "Acme"
    assert d["meta"]["operator"] == "alice"
    assert d["meta"]["status"] == "planning"


def test_to_json():
    em = EngagementManager(client="Acme", operator="alice")
    data = json.loads(em.to_json())
    assert data["meta"]["client"] == "Acme"


def test_save_and_load(tmp_path):
    em = EngagementManager(client="Acme", operator="alice")
    em.start()
    em.record_action("ad", "ldap_enum", "anonymous")

    path = tmp_path / "engagement.json"
    em.save(path)
    assert path.exists()

    em2 = EngagementManager.load(path)
    assert em2.status == "active"
    assert em2.meta.client == "Acme"


def test_load_malformed_json_raises_engagement_error(tmp_path):
    """Phase 13-A regression: load() previously let json.JSONDecodeError
    propagate raw instead of a typed EngagementError -- reachable via the
    CLI's --resume flag pointed at a corrupted/hand-edited file."""
    path = tmp_path / "corrupt.json"
    path.write_text("{not valid json")

    with pytest.raises(EngagementError):
        EngagementManager.load(path)


def test_load_non_dict_json_raises_engagement_error(tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[1, 2, 3]")

    with pytest.raises(EngagementError):
        EngagementManager.load(path)


def test_load_invalid_status_raises_engagement_error(tmp_path):
    path = tmp_path / "bad_status.json"
    path.write_text(json.dumps({"meta": {"client": "Acme", "status": "not_a_real_status"}}))

    with pytest.raises(EngagementError):
        EngagementManager.load(path)


def test_load_malformed_timeline_entry_raises_engagement_error(tmp_path):
    path = tmp_path / "bad_timeline.json"
    path.write_text(json.dumps({
        "meta": {"client": "Acme", "status": "planning"},
        "timeline": [{"unexpected_field": "x"}],
    }))

    with pytest.raises(EngagementError):
        EngagementManager.load(path)


# ── report ──────────────────────────────────────────────────────

def test_to_markdown():
    em = EngagementManager(client="Acme", operator="alice")
    em.start()
    em.record_action("network", "scan", "nmap")
    em.complete()

    md = em.to_markdown()
    assert "Acme" in md
    assert "alice" in md
