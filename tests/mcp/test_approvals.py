"""Direct unit tests for reconforge/mcp/approvals.py — the disk-backed,
out-of-band approval state machine. tests/mcp/test_execute_approved_phase.py
and tests/mcp/test_execution_jobs.py already exercise the primary
create -> approve -> consume path end-to-end through services.py; this
file targets the state machine's edges directly: expiry, denial,
revocation, corrupt/missing records, and the lock-timeout path.

See tests/mcp/test_out_of_band_approval_security.py for the adversarial
suite (replay, tamper, concurrent consumption, self-authorization).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from reconforge.mcp import approvals
from reconforge.mcp.errors import (
    ApprovalExpiredError,
    ApprovalNotApprovedError,
    ApprovalNotFoundError,
    ApprovalStateError,
)


def _create(**overrides) -> approvals.ApprovalRequest:
    defaults = {
        "engagement_id": "engagement_active",
        "target": "10.10.10.1",
        "normalized_target": "10.10.10.1",
        "module": "surface",
        "phase": "vector_correlation",
        "opsec_profile": "normal",
        "tier": "safe_read_only",
        "scope_reference": "scope.yaml",
        "output_base": "outputs",
        "domain": "",
        "scope_file": None,
        "approval_id": None,
        "timeout": 600,
    }
    defaults.update(overrides)
    return approvals.create_request(**defaults)


def _expire(record: approvals.ApprovalRequest) -> None:
    """Force a record into the past without waiting out a real TTL."""
    path = approvals._request_path(record.request_id)
    data = json.loads(path.read_text())
    data["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    path.write_text(json.dumps(data))


# ── canonical_request_hash ─────────────────────────────────────────────


def test_canonical_request_hash_is_deterministic_for_identical_fields():
    kwargs = {
        "engagement_id": "e1",
        "normalized_target": "10.10.10.1",
        "module": "web",
        "phase": "surface",
        "opsec_profile": "normal",
        "tier": "active_recon",
        "scope_reference": "scope.yaml",
    }
    assert approvals.canonical_request_hash(**kwargs) == approvals.canonical_request_hash(**kwargs)


def test_canonical_request_hash_changes_when_any_field_changes():
    base = {
        "engagement_id": "e1",
        "normalized_target": "10.10.10.1",
        "module": "web",
        "phase": "surface",
        "opsec_profile": "normal",
        "tier": "active_recon",
        "scope_reference": "scope.yaml",
    }
    baseline = approvals.canonical_request_hash(**base)
    for key, new_value in [
        ("engagement_id", "e2"),
        ("normalized_target", "10.10.10.2"),
        ("module", "api"),
        ("phase", "discovery"),
        ("opsec_profile", "stealth"),
        ("tier", "intrusive"),
        ("scope_reference", "other-scope.yaml"),
    ]:
        mutated = dict(base)
        mutated[key] = new_value
        assert approvals.canonical_request_hash(**mutated) != baseline, f"{key} did not affect the hash"


def test_canonical_request_hash_is_prefixed_with_sha256():
    h = approvals.canonical_request_hash(
        engagement_id="e1",
        normalized_target="10.10.10.1",
        module="web",
        phase="surface",
        opsec_profile="normal",
        tier="active_recon",
        scope_reference="scope.yaml",
    )
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64  # hex digest length


# ── get_request / list_requests ────────────────────────────────────────


def test_get_request_unknown_id_raises():
    with pytest.raises(ApprovalNotFoundError):
        approvals.get_request("not-a-real-id")


def test_get_request_corrupt_file_raises_not_found():
    record = _create()
    path = approvals._request_path(record.request_id)
    path.write_text("not valid json{{{")
    with pytest.raises(ApprovalNotFoundError):
        approvals.get_request(record.request_id)


def test_list_requests_skips_corrupt_files_without_failing():
    good = _create()
    corrupt_path = approvals._approvals_dir() / "corrupt-request.json"
    corrupt_path.write_text("not valid json{{{")

    listed = approvals.list_requests()
    ids = {r.request_id for r in listed}
    assert good.request_id in ids
    assert "corrupt-request" not in ids


def test_list_requests_empty_when_nothing_created():
    assert approvals.list_requests() == []


def test_list_requests_sorted_by_created_at():
    first = _create()
    second = _create()
    listed = approvals.list_requests()
    assert [r.request_id for r in listed] == [first.request_id, second.request_id]


# ── expiry ──────────────────────────────────────────────────────────────


def test_approve_on_expired_request_raises_and_marks_it_expired():
    record = _create()
    _expire(record)
    with pytest.raises(ApprovalExpiredError):
        approvals.approve(record.request_id)
    assert approvals.get_request(record.request_id).status == "expired"


def test_deny_on_expired_request_raises():
    record = _create()
    _expire(record)
    with pytest.raises(ApprovalExpiredError):
        approvals.deny(record.request_id)


def test_consume_on_expired_request_raises():
    record = _create()
    _expire(record)
    with pytest.raises(ApprovalExpiredError):
        approvals.consume_if_approved(record.request_id, expected_hash=record.request_hash)


def test_expiry_does_not_affect_an_already_terminal_request():
    """A denied request that later ages past its expiry timestamp must
    stay 'denied', not flip to 'expired' -- expiry only applies to
    requests still meaningfully pending."""
    record = _create()
    approvals.deny(record.request_id)
    _expire(record)
    assert approvals.get_request(record.request_id).status == "denied"


# ── deny / revoke state transitions ────────────────────────────────────


def test_deny_records_the_given_reason():
    record = _create()
    denied = approvals.deny(record.request_id, reason="Outside authorized window.")
    assert denied.denial_reason == "Outside authorized window."


def test_deny_uses_a_default_reason_when_none_given():
    record = _create()
    denied = approvals.deny(record.request_id)
    assert denied.denial_reason == "Denied by operator."


def test_cannot_deny_an_already_denied_request():
    record = _create()
    approvals.deny(record.request_id)
    with pytest.raises(ApprovalStateError):
        approvals.deny(record.request_id)


def test_cannot_approve_an_already_denied_request():
    record = _create()
    approvals.deny(record.request_id)
    with pytest.raises(ApprovalStateError):
        approvals.approve(record.request_id)


def test_cannot_revoke_a_request_that_was_never_approved():
    record = _create()
    with pytest.raises(ApprovalStateError):
        approvals.revoke(record.request_id)


def test_cannot_revoke_an_already_consumed_request():
    record = _create()
    approvals.approve(record.request_id)
    approvals.consume_if_approved(record.request_id, expected_hash=record.request_hash)
    with pytest.raises(ApprovalStateError):
        approvals.revoke(record.request_id)


def test_revoked_request_cannot_be_consumed():
    record = _create()
    approvals.approve(record.request_id)
    revoked = approvals.revoke(record.request_id)
    assert revoked.status == "revoked"
    from reconforge.mcp.errors import ApprovalNotApprovedError

    with pytest.raises(ApprovalNotApprovedError):
        approvals.consume_if_approved(record.request_id, expected_hash=record.request_hash)


# ── approved_by ──────────────────────────────────────────────────────


def test_approve_records_explicit_approved_by_when_given():
    record = _create()
    approved = approvals.approve(record.request_id, approved_by="alice")
    assert approved.approved_by == "alice"


def test_approve_falls_back_to_local_operator_identity(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(approvals, "_local_operator_identity", lambda: "detected-user")
    record = _create()
    approved = approvals.approve(record.request_id)
    assert approved.approved_by == "detected-user"


def test_local_operator_identity_returns_none_when_getpass_fails(monkeypatch: pytest.MonkeyPatch):
    import getpass

    def _boom() -> str:
        raise OSError("no controlling terminal")

    monkeypatch.setattr(getpass, "getuser", _boom)
    assert approvals._local_operator_identity() is None


# ── lock timeout ─────────────────────────────────────────────────────


def test_request_lock_times_out_if_held_too_long(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(approvals, "_LOCK_TIMEOUT_S", 0.05)
    monkeypatch.setattr(approvals, "_LOCK_RETRY_INTERVAL_S", 0.01)

    record = _create()
    directory = approvals._approvals_dir()
    lock_path = approvals._lock_path(record.request_id, directory)
    lock_path.touch()  # simulate another process already holding it
    try:
        with pytest.raises(ApprovalStateError, match="Timed out"):
            approvals.approve(record.request_id)
    finally:
        lock_path.unlink(missing_ok=True)


def test_request_lock_release_tolerates_an_unlink_failure(monkeypatch: pytest.MonkeyPatch):
    """__exit__ must not raise even if removing the lock file itself
    fails (e.g. a concurrent cleanup already removed it) -- releasing a
    lock must never be the operation that crashes an approval action."""
    from pathlib import Path

    original_unlink = Path.unlink

    def _boom(self, *args, **kwargs):
        if self.name.endswith(".lock"):
            raise OSError("simulated unlink failure")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", _boom)
    record = _create()
    approved = approvals.approve(record.request_id)  # must not raise
    assert approved.status == "approved"


# ── _parse_iso ──────────────────────────────────────────────────────


def test_parse_iso_treats_naive_datetimes_as_utc():
    dt = approvals._parse_iso("2026-01-01T00:00:00")
    assert dt.tzinfo is not None
    assert dt.utcoffset().total_seconds() == 0


# ── consume_if_approved: hash mismatch and concurrent consumption ────


def test_consume_if_approved_rejects_a_mismatched_hash():
    from reconforge.mcp.errors import ApprovalRequestMismatchError

    record = _create()
    approvals.approve(record.request_id)
    with pytest.raises(ApprovalRequestMismatchError):
        approvals.consume_if_approved(record.request_id, expected_hash="sha256:" + "0" * 64)
    # A rejected-for-tamper attempt must not have consumed the approval --
    # the real, correct hash can still be used afterward.
    assert approvals.get_request(record.request_id).status == "approved"


def test_consume_if_approved_sequential_replay_after_consumption_is_not_approved():
    """Once the first call has fully consumed the request (status is
    genuinely 'consumed' on disk), a later call sees that as its own
    reason to refuse -- distinct from the exactly-one-winner race
    below, which is about two callers racing before either has
    finished writing 'consumed'."""
    from reconforge.mcp.errors import ApprovalNotApprovedError

    record = _create()
    approvals.approve(record.request_id)
    approvals.consume_if_approved(record.request_id, expected_hash=record.request_hash)
    with pytest.raises(ApprovalNotApprovedError) as exc_info:
        approvals.consume_if_approved(record.request_id, expected_hash=record.request_hash)
    assert exc_info.value.status == "consumed"


def test_consume_if_approved_concurrent_race_exactly_one_winner():
    """Eight callers racing to consume the same approved request at the
    same instant -- exactly one must succeed; every other caller must
    fail, not silently succeed too.

    A losing caller can observe either of two distinct errors depending
    on exact scheduling, and both are correct:
      - ApprovalStateError: it lost the os.open(O_CREAT|O_EXCL) marker
        race (consume_if_approved's actual exclusivity mechanism).
      - ApprovalNotApprovedError: its status read happened *after* the
        winner had already flipped status to "consumed" under
        _RequestLock, so it never even reached the marker race.
    Which branch a given loser takes is a timing artifact, not part of
    the exactly-once guarantee -- only "exactly 1 success, 7 losses" is
    guaranteed. Asserting a fixed split flaked in CI (observed 6/7 state_error
    with 1 not_approved) because CI's scheduler interleaves the 8 threads
    differently than local runs.
    """
    import threading

    record = _create()
    approvals.approve(record.request_id)

    results: list[str] = []

    def _consume() -> None:
        try:
            approvals.consume_if_approved(record.request_id, expected_hash=record.request_hash)
            results.append("success")
        except ApprovalStateError:
            results.append("state_error")
        except ApprovalNotApprovedError:
            results.append("not_approved")
        except Exception as exc:  # pragma: no cover - would indicate a real bug
            results.append(f"unexpected:{type(exc).__name__}")

    threads = [threading.Thread(target=_consume) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count("success") == 1
    assert results.count("state_error") + results.count("not_approved") == 7
