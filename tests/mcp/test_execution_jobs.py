"""Tests for reconforge/mcp/jobs.py and its services.py wrappers
(start_execution/get_execution_status) — the async job model layered
on top of execute_approved_phase's synchronous execution path.

Mirrors tests/mcp/test_execute_approved_phase.py's structure: prove
the deny paths fail *before* any job is created (the job model is not
a weaker authorization path around the same policy engine, and shares
the identical out-of-band approval requirement), then prove the one
allow path genuinely executes for real using the same
zero-external-dependency SAFE_READ_ONLY phase already established
there (surface's vector_correlation).
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from core.engagement import EngagementManager
from reconforge.mcp import approvals, jobs, schemas, services
from reconforge.mcp.errors import (
    ApprovalNotApprovedError,
    ExecutionConflictError,
    JobNotFoundError,
    PolicyBlockedError,
)


def _save_active_engagement(tmp_path: Path, engagement_id: str = "engagement_active") -> None:
    mgr = EngagementManager(name="Test Engagement", operator="tester", scope=["10.10.10.1"])
    mgr.start()
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
    request = _full_request(tmp_path, **overrides)
    created = services.request_execution(request)
    approvals.approve(created.request_id)
    return created.request_id


def _poll_until_done(job_id: str, timeout_s: float = 5.0) -> schemas.GetExecutionStatusResponse:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = services.get_execution_status(schemas.GetExecutionStatusRequest(job_id=job_id))
        if status.status in ("completed", "failed"):
            return status
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish within {timeout_s}s")


# ── the allow path: proves real execution actually happens ───────────


def test_start_execution_returns_immediately_and_job_completes_for_real(tmp_path: Path):
    request_id = _create_and_approve(tmp_path)

    start = time.monotonic()
    response = services.start_execution(schemas.StartExecutionRequest(request_id=request_id))
    elapsed = time.monotonic() - start

    assert response.trust == "server_generated"
    assert response.status in ("pending", "running")
    # A real surface/vector_correlation run + report generation still
    # takes some non-zero time — if start_execution took anywhere close
    # to that, it isn't actually async.
    assert elapsed < 1.0

    status = _poll_until_done(response.job_id)
    assert status.status == "completed"
    assert status.error is None
    assert status.error_code is None
    assert status.result is not None
    assert status.result.tier == "safe_read_only"
    assert status.result.warnings == []
    artifact_dir = Path(status.result.artifacts_written[0])
    assert (artifact_dir / "findings.json").is_file()


# ── never self-approves: identical policy gate as execute_approved_phase ─


def test_start_execution_denied_without_operator_approval_creates_no_job(tmp_path: Path):
    request = _full_request(tmp_path, module="web", phase="surface")
    created = services.request_execution(request)
    jobs_before = len(jobs._JOBS)
    with pytest.raises(ApprovalNotApprovedError):
        services.start_execution(schemas.StartExecutionRequest(request_id=created.request_id))
    assert len(jobs._JOBS) == jobs_before


def test_start_execution_denied_without_engagement_creates_no_job(tmp_path: Path):
    request = _full_request(tmp_path, module="web", phase="surface", engagement_id="does_not_exist")
    with pytest.raises(PolicyBlockedError, match="engagement_id"):
        services.request_execution(request)


def test_credential_use_phase_rejected_at_request_creation_even_when_fully_authorized(tmp_path: Path):
    request = _full_request(tmp_path, module="ad", phase="delegation", domain="corp.local")
    with pytest.raises(PolicyBlockedError, match="CREDENTIAL_USE"):
        services.request_execution(request)


# ── concurrency: shares services._EXECUTION_LOCK with the sync tool ──


def test_start_execution_conflict_when_lock_already_held_does_not_consume_the_approval(tmp_path: Path):
    request_id = _create_and_approve(tmp_path)
    assert services._EXECUTION_LOCK.acquire(blocking=False)
    try:
        with pytest.raises(ExecutionConflictError):
            services.start_execution(schemas.StartExecutionRequest(request_id=request_id))
    finally:
        services._EXECUTION_LOCK.release()

    # The lock conflict must not have burned the approval -- it's still
    # usable once the server is free (see services.py::start_execution's
    # lock-before-consume ordering and its comment for why).
    assert approvals.get_request(request_id).status == "approved"


def test_start_execution_conflict_is_raised_synchronously_not_as_a_failed_job(tmp_path: Path):
    """A busy server must reject the call itself -- it must not silently
    accept the request and report the conflict later as a job status."""
    request_id = _create_and_approve(tmp_path)
    jobs_before = len(jobs._JOBS)
    assert services._EXECUTION_LOCK.acquire(blocking=False)
    try:
        with pytest.raises(ExecutionConflictError):
            services.start_execution(schemas.StartExecutionRequest(request_id=request_id))
    finally:
        services._EXECUTION_LOCK.release()
    assert len(jobs._JOBS) == jobs_before


def test_execute_approved_phase_and_start_execution_share_the_lock(tmp_path: Path):
    """A job in flight must block the synchronous tool too, and vice
    versa -- they are not two independent concurrency domains."""
    request_id = _create_and_approve(tmp_path)
    assert services._EXECUTION_LOCK.acquire(blocking=False)
    try:
        with pytest.raises(ExecutionConflictError):
            services.execute_approved_phase(schemas.ExecuteApprovedPhaseRequest(request_id=request_id))
    finally:
        services._EXECUTION_LOCK.release()


def test_lock_is_released_after_a_job_completes(tmp_path: Path):
    request_id = _create_and_approve(tmp_path)
    response = services.start_execution(schemas.StartExecutionRequest(request_id=request_id))
    _poll_until_done(response.job_id)
    assert services._EXECUTION_LOCK.acquire(blocking=False)
    services._EXECUTION_LOCK.release()


def test_job_records_mcpserviceerror_raised_during_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Distinct from the generic-Exception failure test below: forces
    the worker's ``except MCPServiceError`` branch specifically (as
    opposed to the catch-all ``except Exception``), since nothing in
    the current, real _execute_module_phase_locked path actually
    raises an MCPServiceError post-authorization -- this is defensive
    code that would otherwise go completely unverified."""

    def _boom(record, module_cls, tier, scope):
        raise PolicyBlockedError("simulated late policy failure")

    request_id = _create_and_approve(tmp_path)
    monkeypatch.setattr(services, "_execute_module_phase_locked", _boom)
    response = services.start_execution(schemas.StartExecutionRequest(request_id=request_id))
    status = _poll_until_done(response.job_id)

    assert status.status == "failed"
    assert status.error_code == "POLICY_BLOCKED"
    assert "simulated late policy failure" in status.error

    assert services._EXECUTION_LOCK.acquire(blocking=False)
    services._EXECUTION_LOCK.release()


def test_lock_is_released_after_a_job_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Mirrors test_execute_approved_phase.py's equivalent test: an
    unexpected exception during module construction inside the worker
    thread must still release the lock, not leave it stuck."""

    class _BrokenModule:
        MODULE_NAME = "surface"
        VALID_PHASES = ["vector_correlation"]

        def __init__(self, **kwargs):
            raise RuntimeError("simulated crash during module construction")

    request_id = _create_and_approve(tmp_path)
    monkeypatch.setattr(services, "_module_class", lambda name: _BrokenModule)
    response = services.start_execution(schemas.StartExecutionRequest(request_id=request_id))
    status = _poll_until_done(response.job_id)

    assert status.status == "failed"
    assert status.error_code == "MCP_SERVICE_ERROR"
    assert "simulated crash" in status.error

    assert services._EXECUTION_LOCK.acquire(blocking=False)
    services._EXECUTION_LOCK.release()


# ── get_execution_status ──────────────────────────────────────────────


def test_get_execution_status_unknown_job_id_raises():
    with pytest.raises(JobNotFoundError):
        services.get_execution_status(schemas.GetExecutionStatusRequest(job_id="not-a-real-job-id"))
