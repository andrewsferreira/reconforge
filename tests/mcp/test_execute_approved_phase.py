"""Tests for reconforge/mcp/services.py::execute_approved_phase — the one
tool in this package that can trigger real (non-dry-run) execution.

Every deny-path test below proves the policy gate actually blocks
execution (not just that it returns an error message) by using a
SAFE_READ_ONLY phase (surface's vector_correlation, which needs no
external tool and runs deterministically with zero prerequisite data —
verified empirically before writing these tests) as the one phase where
we also prove the allow-path genuinely executes.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from core.engagement import EngagementManager
from reconforge.mcp import schemas, services
from reconforge.mcp.errors import (
    ExecutionConflictError,
    PolicyBlockedError,
    UnknownPhaseError,
)


def _save_active_engagement(tmp_path: Path, engagement_id: str = "engagement_active") -> None:
    mgr = EngagementManager(name="Test Engagement", operator="tester", scope=["10.10.10.1"])
    mgr.start()
    workflow_dir = tmp_path / "workflow"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    mgr.save(workflow_dir / f"{engagement_id}.json")


def _save_inactive_engagement(tmp_path: Path, engagement_id: str = "engagement_planning") -> None:
    mgr = EngagementManager(name="Not Started Yet", operator="tester", scope=["10.10.10.1"])
    workflow_dir = tmp_path / "workflow"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    mgr.save(workflow_dir / f"{engagement_id}.json")


def _write_scope_file(path: Path, targets=("10.10.10.1",), approval_id: str = "APPROVAL-1") -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "allowed_targets": list(targets),
                "approval_id": approval_id,
                "valid_until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            }
        )
    )


def _full_request(tmp_path: Path, **overrides) -> schemas.ExecuteApprovedPhaseRequest:
    scope_file = tmp_path / "scope.yaml"
    if not scope_file.exists():
        _write_scope_file(scope_file)
    if not (tmp_path / "workflow" / "engagement_active.json").exists():
        _save_active_engagement(tmp_path)

    defaults = dict(
        engagement_id="engagement_active",
        target="10.10.10.1",
        module="surface",
        phase="vector_correlation",
        output_base=str(tmp_path),
        scope_file=str(scope_file),
        approval_id="APPROVAL-1",
        explicit_confirmation=True,
    )
    defaults.update(overrides)
    return schemas.ExecuteApprovedPhaseRequest(**defaults)


# ── the allow path: proves real execution actually happens ───────────


def test_safe_read_only_phase_executes_for_real_when_fully_authorized(tmp_path: Path):
    request = _full_request(tmp_path)
    response = services.execute_approved_phase(request)

    assert response.trust == "server_generated"
    assert response.module == "surface"
    assert response.phase == "vector_correlation"
    assert response.tier == "safe_read_only"
    assert response.warnings == []
    artifact_dir = Path(response.artifacts_written[0])
    assert artifact_dir.is_dir()
    # Proves this was a real run, not a stub: the module actually wrote
    # its output files (findings.json, session.md, ...) to disk.
    assert (artifact_dir / "findings.json").is_file()


# ── never self-approves (the same invariant policy.py enforces, now at
# the integration level) ──────────────────────────────────────────────


def test_denied_without_explicit_confirmation(tmp_path: Path):
    request = _full_request(tmp_path, module="web", phase="surface", explicit_confirmation=False)
    with pytest.raises(PolicyBlockedError, match="explicit_confirmation"):
        services.execute_approved_phase(request)


def test_denied_without_engagement(tmp_path: Path):
    request = _full_request(tmp_path, module="web", phase="surface", engagement_id="does_not_exist")
    with pytest.raises(PolicyBlockedError, match="engagement_id"):
        services.execute_approved_phase(request)


def test_denied_when_engagement_is_not_active(tmp_path: Path):
    _save_inactive_engagement(tmp_path)
    request = _full_request(tmp_path, module="web", phase="surface", engagement_id="engagement_planning")
    with pytest.raises(PolicyBlockedError, match="engagement_id"):
        services.execute_approved_phase(request)


def test_denied_with_wrong_approval_id(tmp_path: Path):
    request = _full_request(tmp_path, module="web", phase="surface", approval_id="WRONG-APPROVAL")
    with pytest.raises(PolicyBlockedError):
        services.execute_approved_phase(request)


def test_denied_when_target_not_in_scope(tmp_path: Path):
    scope_file = tmp_path / "narrow_scope.yaml"
    _write_scope_file(scope_file, targets=("10.10.10.99",))
    _save_active_engagement(tmp_path)
    request = _full_request(
        tmp_path,
        module="web",
        phase="surface",
        scope_file=str(scope_file),
    )
    with pytest.raises(PolicyBlockedError):
        services.execute_approved_phase(request)


def test_denied_without_scope_file_at_all(tmp_path: Path):
    _save_active_engagement(tmp_path)
    request = _full_request(tmp_path, module="web", phase="surface", scope_file=None, approval_id=None)
    with pytest.raises(PolicyBlockedError):
        services.execute_approved_phase(request)


# ── CREDENTIAL_USE / PROHIBITED are never executable through this tool ─


def test_credential_use_phase_is_rejected_even_when_fully_authorized(tmp_path: Path):
    """ad/delegation and ad/bloodhound are CREDENTIAL_USE — this tool has
    no credential-reference mechanism, so they're rejected outright, even
    with a perfect engagement/scope/confirmation/approval_id."""
    request = _full_request(tmp_path, module="ad", phase="delegation", domain="corp.local")
    with pytest.raises(PolicyBlockedError, match="CREDENTIAL_USE"):
        services.execute_approved_phase(request)


def test_prohibited_tier_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """No real (module, phase) classifies as PROHIBITED today — this
    forces that branch via monkeypatch to prove the guard clause itself
    works, since it can't be reached through real inputs."""
    from reconforge.mcp.policy import ExecutionTier

    monkeypatch.setattr(services, "classify_phase", lambda *a, **k: ExecutionTier.PROHIBITED)
    request = _full_request(tmp_path)
    with pytest.raises(PolicyBlockedError, match="PROHIBITED"):
        services.execute_approved_phase(request)


# ── INTRUSIVE additionally requires config/mcp.yaml's server-wide gate ─


def test_intrusive_tier_rejected_even_when_fully_authorized_because_config_gate_defaults_off(tmp_path: Path):
    """web/exploit is INTRUSIVE — config/mcp.yaml's mcp.allow_intrusive_execution
    defaults to false, so even a fully-authorized request (engagement,
    scope, confirmation, approval_id all present) must still be denied."""
    request = _full_request(tmp_path, module="web", phase="exploit", approval_id="APPROVAL-1")
    with pytest.raises(PolicyBlockedError, match="allow_intrusive_execution"):
        services.execute_approved_phase(request)


def test_intrusive_tier_reaches_execution_when_config_gate_is_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Proves the config gate is actually read and passed through to
    evaluate() — uses a no-op fake module (like
    test_lock_is_released_after_execution_raises_internally does) so this
    doesn't depend on web/exploit's real tool execution succeeding
    against a fake target."""

    class _NoOpModule:
        MODULE_NAME = "web"
        VALID_PHASES = ["exploit"]

        def __init__(self, **kwargs):
            pass

        def run(self, phases):
            pass

        @property
        def findings_mgr(self):
            return type("FindingsMgr", (), {"get_all": staticmethod(list)})()

        @property
        def output(self):
            return type("Output", (), {"module_dir": staticmethod(lambda name: tmp_path)})()

    monkeypatch.setattr(services, "_intrusive_execution_allowed", lambda: True)
    monkeypatch.setattr(services, "_module_class", lambda name: _NoOpModule)
    request = _full_request(tmp_path, module="web", phase="exploit", approval_id="APPROVAL-1")
    response = services.execute_approved_phase(request)
    assert response.tier == "intrusive"
    assert response.findings_count == 0


# ── other guards ────────────────────────────────────────────────────


def test_unknown_phase_is_rejected(tmp_path: Path):
    request = _full_request(tmp_path, module="web", phase="not_a_real_phase")
    with pytest.raises(UnknownPhaseError):
        services.execute_approved_phase(request)


def test_invalid_target_is_rejected(tmp_path: Path):
    from reconforge.mcp.errors import InvalidMCPRequestError

    request = _full_request(tmp_path, target="10.10.10.1; rm -rf /")
    with pytest.raises(InvalidMCPRequestError):
        services.execute_approved_phase(request)


def test_concurrent_execution_is_rejected(tmp_path: Path):
    """A second call while the lock is held must fail cleanly rather than
    running two executions at once."""
    assert services._EXECUTION_LOCK.acquire(blocking=False)
    try:
        request = _full_request(tmp_path)
        with pytest.raises(ExecutionConflictError):
            services.execute_approved_phase(request)
    finally:
        services._EXECUTION_LOCK.release()


def test_lock_is_released_after_a_successful_execution(tmp_path: Path):
    """A prior successful call must not leave the lock held forever."""
    services.execute_approved_phase(_full_request(tmp_path))
    assert services._EXECUTION_LOCK.acquire(blocking=False)
    services._EXECUTION_LOCK.release()


def test_lock_is_released_after_execution_raises_internally(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """If module construction raises something unexpected *after* the
    lock is already held, the lock must still be released via the
    finally block, not left stuck. classify_phase already succeeded by
    this point (this isn't the phase-validation guard above it), so
    patching _module_class here specifically exercises the code inside
    the lock's try/finally."""

    class _BrokenModule:
        MODULE_NAME = "surface"
        VALID_PHASES = ["vector_correlation"]

        def __init__(self, **kwargs):
            raise RuntimeError("simulated crash during module construction")

    monkeypatch.setattr(services, "_module_class", lambda name: _BrokenModule)
    request = _full_request(tmp_path)
    with pytest.raises(RuntimeError):
        services.execute_approved_phase(request)
    assert services._EXECUTION_LOCK.acquire(blocking=False)
    services._EXECUTION_LOCK.release()
