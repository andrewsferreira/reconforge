"""Tests for reconforge/mcp/services.py::execute_approved_phase — the one
tool in this package that can trigger real (non-dry-run) execution.

Under the out-of-band approval architecture, most of what used to be
execute_approved_phase's own deny-path checks now happen at request
creation time (services.request_execution) — a request that should
never have existed is rejected right there, before an operator could
even see it to approve. What remains distinctly execute_approved_phase's
own responsibility is the one gate request_execution cannot perform:
proving a human actually approved *this* request, out-of-band, via
reconforge.mcp.approvals.approve() — never anything this MCP session
itself can call. See test_denied_without_operator_approval, the
single most important test in this file.

Every allow-path test below proves the full pipeline genuinely
executes (not just that it returns success) by using a SAFE_READ_ONLY
phase (surface's vector_correlation, which needs no external tool and
runs deterministically with zero prerequisite data — verified
empirically before writing these tests).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from core.engagement import EngagementManager
from reconforge.mcp import approvals, schemas, services
from reconforge.mcp.errors import (
    ApprovalNotApprovedError,
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


def _full_request(tmp_path: Path, **overrides) -> schemas.RequestExecutionRequest:
    scope_file = tmp_path / "scope.yaml"
    if not scope_file.exists():
        _write_scope_file(scope_file)
    if not (tmp_path / "workflow" / "engagement_active.json").exists():
        _save_active_engagement(tmp_path)

    defaults = {
        "engagement_id": "engagement_active",
        "target": "10.10.10.1",
        "module": "surface",
        "phase": "vector_correlation",
        "output_base": str(tmp_path),
        "scope_file": str(scope_file),
        "approval_id": "APPROVAL-1",
    }
    defaults.update(overrides)
    return schemas.RequestExecutionRequest(**defaults)


def _create_and_approve(tmp_path: Path, **overrides) -> str:
    """The out-of-band half of the flow: create a pending request, then
    approve it exactly as an operator would — a direct call into
    approvals.approve(), never through any MCP tool. Returns the
    request_id, ready for execute_approved_phase."""
    request = _full_request(tmp_path, **overrides)
    created = services.request_execution(request)
    approvals.approve(created.request_id)
    return created.request_id


# ── the allow path: proves real execution actually happens ───────────


def test_safe_read_only_phase_executes_for_real_when_fully_authorized(tmp_path: Path):
    request_id = _create_and_approve(tmp_path)
    response = services.execute_approved_phase(schemas.ExecuteApprovedPhaseRequest(request_id=request_id))

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


# ── never self-approves: the one thing this MCP session can never do ──


def test_denied_without_operator_approval(tmp_path: Path):
    """The core security invariant of the whole architecture: a fully
    valid, freshly created request must never execute until a human has
    approved it out-of-band. There is no field on ExecuteApprovedPhaseRequest
    other than request_id — nothing this MCP session can supply
    substitutes for reconforge.mcp.approvals.approve()."""
    request = _full_request(tmp_path, module="web", phase="surface")
    created = services.request_execution(request)
    with pytest.raises(ApprovalNotApprovedError) as exc_info:
        services.execute_approved_phase(schemas.ExecuteApprovedPhaseRequest(request_id=created.request_id))
    assert exc_info.value.status == "awaiting_operator_approval"


def test_denied_when_approval_was_explicitly_denied_by_operator(tmp_path: Path):
    request = _full_request(tmp_path, module="web", phase="surface")
    created = services.request_execution(request)
    approvals.deny(created.request_id, reason="Not authorized for this window.")
    with pytest.raises(ApprovalNotApprovedError) as exc_info:
        services.execute_approved_phase(schemas.ExecuteApprovedPhaseRequest(request_id=created.request_id))
    assert exc_info.value.status == "denied"


# ── request_execution: everything that used to gate execute_approved_phase
# itself now gates whether a request can even be created ─────────────


def test_request_denied_without_engagement(tmp_path: Path):
    request = _full_request(tmp_path, module="web", phase="surface", engagement_id="does_not_exist")
    with pytest.raises(PolicyBlockedError, match="engagement_id"):
        services.request_execution(request)


def test_request_denied_when_engagement_is_not_active(tmp_path: Path):
    _save_inactive_engagement(tmp_path)
    request = _full_request(tmp_path, module="web", phase="surface", engagement_id="engagement_planning")
    with pytest.raises(PolicyBlockedError, match="engagement_id"):
        services.request_execution(request)


def test_request_denied_with_wrong_approval_id(tmp_path: Path):
    request = _full_request(tmp_path, module="web", phase="surface", approval_id="WRONG-APPROVAL")
    with pytest.raises(PolicyBlockedError, match="scope"):
        services.request_execution(request)


def test_request_denied_when_target_not_in_scope(tmp_path: Path):
    scope_file = tmp_path / "narrow_scope.yaml"
    _write_scope_file(scope_file, targets=("10.10.10.99",))
    _save_active_engagement(tmp_path)
    request = _full_request(
        tmp_path,
        module="web",
        phase="surface",
        scope_file=str(scope_file),
    )
    with pytest.raises(PolicyBlockedError, match="scope"):
        services.request_execution(request)


def test_request_denied_without_scope_file_at_all(tmp_path: Path):
    _save_active_engagement(tmp_path)
    request = _full_request(tmp_path, module="web", phase="surface", scope_file=None, approval_id=None)
    with pytest.raises(PolicyBlockedError, match="scope"):
        services.request_execution(request)


def test_web_target_with_a_port_reaches_the_engagement_check_not_rejected_as_invalid(
    tmp_path: Path,
):
    """Regression test: services.py used to validate every module's
    target with parse_target() (bare IP/CIDR/hostname only), which
    rejects a "host:port" string outright even though WebModule itself
    accepts it. If that bug were still present this request would fail
    target validation (InvalidMCPRequestError) before ever reaching the
    engagement check below — asserting the specific PolicyBlockedError/
    "engagement_id" failure instead proves the target was accepted and
    validation proceeded past it."""
    request = schemas.RequestExecutionRequest(
        engagement_id="does_not_exist",
        target="127.0.0.1:8899",
        module="web",
        phase="surface",
        output_base=str(tmp_path),
    )
    with pytest.raises(PolicyBlockedError, match="engagement_id"):
        services.request_execution(request)


# ── CREDENTIAL_USE / PROHIBITED are never even creatable as a request ─


def test_credential_use_phase_is_rejected_even_when_fully_authorized(tmp_path: Path):
    """ad/delegation and ad/bloodhound are CREDENTIAL_USE — this tool has
    no credential-reference mechanism, so they're rejected outright, even
    with a perfect engagement/scope/approval_id. Rejected at request
    creation, so there is never anything for an operator to approve."""
    request = _full_request(tmp_path, module="ad", phase="delegation", domain="corp.local")
    with pytest.raises(PolicyBlockedError, match="CREDENTIAL_USE"):
        services.request_execution(request)


def test_prohibited_tier_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """No real (module, phase) classifies as PROHIBITED today — this
    forces that branch via monkeypatch to prove the guard clause itself
    works, since it can't be reached through real inputs."""
    from reconforge.mcp.policy import ExecutionTier

    monkeypatch.setattr(services, "classify_phase", lambda *a, **k: ExecutionTier.PROHIBITED)
    request = _full_request(tmp_path)
    with pytest.raises(PolicyBlockedError, match="PROHIBITED"):
        services.request_execution(request)


# ── INTRUSIVE additionally requires config/mcp.yaml's server-wide gate,
# checked both at request creation and again at consumption time ─────


def test_request_denied_for_intrusive_tier_when_config_gate_defaults_off(tmp_path: Path):
    """web/exploit is INTRUSIVE — config/mcp.yaml's mcp.allow_intrusive_execution
    defaults to false, so a request can't even be created without it,
    regardless of how complete the engagement/scope is."""
    request = _full_request(tmp_path, module="web", phase="exploit", approval_id="APPROVAL-1")
    with pytest.raises(PolicyBlockedError, match="allow_intrusive_execution"):
        services.request_execution(request)


def test_intrusive_tier_reaches_execution_when_config_gate_is_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Proves the config gate is actually read and passed through to
    evaluate() at both request-creation and consumption time — uses a
    no-op fake module so this doesn't depend on web/exploit's real tool
    execution succeeding against a fake target."""

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
    created = services.request_execution(request)
    approvals.approve(created.request_id)
    response = services.execute_approved_phase(
        schemas.ExecuteApprovedPhaseRequest(request_id=created.request_id)
    )
    assert response.tier == "intrusive"
    assert response.findings_count == 0


# ── other guards ────────────────────────────────────────────────────


def test_request_for_unknown_phase_is_rejected(tmp_path: Path):
    request = _full_request(tmp_path, module="web", phase="not_a_real_phase")
    with pytest.raises(UnknownPhaseError):
        services.request_execution(request)


def test_request_for_invalid_target_is_rejected(tmp_path: Path):
    from reconforge.mcp.errors import InvalidMCPRequestError

    request = _full_request(tmp_path, target="10.10.10.1; rm -rf /")
    with pytest.raises(InvalidMCPRequestError):
        services.request_execution(request)


def test_unknown_request_id_is_rejected():
    from reconforge.mcp.errors import ApprovalNotFoundError

    with pytest.raises(ApprovalNotFoundError):
        services.execute_approved_phase(schemas.ExecuteApprovedPhaseRequest(request_id="not-a-real-id"))


def test_concurrent_execution_is_rejected_without_consuming_the_approval(tmp_path: Path):
    """A second call while the lock is held must fail cleanly rather than
    running two executions at once — and, since the lock is acquired
    before the approval is touched, the approval must remain valid and
    consumable afterward (a transient server-busy conflict must never
    burn a genuinely approved request)."""
    request_id = _create_and_approve(tmp_path)
    assert services._EXECUTION_LOCK.acquire(blocking=False)
    try:
        with pytest.raises(ExecutionConflictError):
            services.execute_approved_phase(schemas.ExecuteApprovedPhaseRequest(request_id=request_id))
    finally:
        services._EXECUTION_LOCK.release()

    record = approvals.get_request(request_id)
    assert record.status == "approved"

    # And it can still genuinely execute now that the lock is free.
    response = services.execute_approved_phase(schemas.ExecuteApprovedPhaseRequest(request_id=request_id))
    assert response.tier == "safe_read_only"


def test_lock_is_released_after_a_successful_execution(tmp_path: Path):
    """A prior successful call must not leave the lock held forever."""
    request_id = _create_and_approve(tmp_path)
    services.execute_approved_phase(schemas.ExecuteApprovedPhaseRequest(request_id=request_id))
    assert services._EXECUTION_LOCK.acquire(blocking=False)
    services._EXECUTION_LOCK.release()


def test_lock_is_released_after_execution_raises_internally(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """If module construction raises something unexpected *after* the
    lock is already held, the lock must still be released via the
    finally block, not left stuck."""

    class _BrokenModule:
        MODULE_NAME = "surface"
        VALID_PHASES = ["vector_correlation"]

        def __init__(self, **kwargs):
            raise RuntimeError("simulated crash during module construction")

    request_id = _create_and_approve(tmp_path)
    monkeypatch.setattr(services, "_module_class", lambda name: _BrokenModule)
    with pytest.raises(RuntimeError):
        services.execute_approved_phase(schemas.ExecuteApprovedPhaseRequest(request_id=request_id))
    assert services._EXECUTION_LOCK.acquire(blocking=False)
    services._EXECUTION_LOCK.release()
