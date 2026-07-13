"""Tests that --enforce-scope's ScopeAuthorization actually reaches each
module's Runner, and that WorkflowOrchestrator propagates it to modules it
spawns dynamically (including auto-handoff targets discovered mid-run).

core/runner.py enforces scope directly (see tests/core/test_runner.py); this
file verifies the wiring from module constructors and the workflow orchestrator
down into Runner, which is the part that closes the "scope checked once at
CLI start, never again" gap.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from core.authorization_gate import ScopeAuthorization
from core.exceptions import ScopeViolationError


def _make_scope(allowed_targets, approval_id="APPROVAL-1"):
    return ScopeAuthorization(
        allowed_targets=allowed_targets,
        approval_id=approval_id,
        valid_until=datetime.now(timezone.utc) + timedelta(hours=1),
    )


@patch("modules.network.network_module.OutputManager")
def test_network_module_binds_scope_to_runner(mock_om):
    from modules.network.network_module import NetworkModule

    scope = _make_scope(["10.10.10.1"])
    mod = NetworkModule("10.10.10.1", scope=scope, approval_id="APPROVAL-1")
    assert mod.runner.scope is scope
    assert mod.runner.approval_id == "APPROVAL-1"


@patch("modules.network.network_module.OutputManager")
def test_network_module_out_of_scope_target_blocked_at_construction(mock_om):
    from modules.network.network_module import NetworkModule

    scope = _make_scope(["10.10.10.1"])
    with pytest.raises(ScopeViolationError):
        NetworkModule("10.10.10.99", scope=scope, approval_id="APPROVAL-1")


@patch("modules.surface.surface_module.OutputManager")
@patch("modules.surface.surface_module.parse_target")
def test_surface_module_binds_scope_to_runner(mock_pt, mock_om):
    mock_pt.return_value = MagicMock(display="10.10.10.1")
    from modules.surface.surface_module import SurfaceModule

    scope = _make_scope(["10.10.10.1"])
    mod = SurfaceModule("10.10.10.1", scope=scope, approval_id="APPROVAL-1")
    assert mod.runner.scope is scope


def test_run_module_propagates_scope_to_spawned_module():
    """core.workflow_orchestrator._run_module must forward scope/approval_id
    to the module it constructs, so handoff-discovered targets are checked
    against the same engagement scope as the workflow's initial target."""
    from core.workflow_orchestrator import _run_module

    scope = _make_scope(["10.10.10.1"])
    fake_module = MagicMock()
    fake_module.run.return_value = {"phases": {}}
    fake_module.loot = MagicMock()

    with patch("modules.network.network_module.NetworkModule", return_value=fake_module) as ctor:
        _run_module("network", "10.10.10.1", scope=scope, approval_id="APPROVAL-1")

    assert ctor.call_args.kwargs["scope"] is scope
    assert ctor.call_args.kwargs["approval_id"] == "APPROVAL-1"


def test_run_module_aggregates_findings_into_provided_manager():
    """Phase 9-F: core.workflow_orchestrator._run_module must ingest the
    spawned module's findings into the caller-provided FindingsManager —
    previously WorkflowOrchestrator.findings existed but nothing ever
    wrote to it, so no cross-module aggregation happened at all."""
    from core.workflow_orchestrator import _run_module
    from core.findings_manager import FindingsManager

    fake_module = MagicMock()
    fake_module.run.return_value = {"phases": {}}
    fake_module.loot = MagicMock()
    source_findings = FindingsManager()
    source_findings.add(
        finding_type="misconfiguration", severity="medium", confidence="confirmed",
        target="10.10.10.1", module="network", description="SMB signing disabled",
    )
    fake_module.findings_mgr = source_findings

    aggregate = FindingsManager()
    with patch("modules.network.network_module.NetworkModule", return_value=fake_module):
        _run_module("network", "10.10.10.1", findings_manager=aggregate)

    assert len(aggregate.get_all()) == 1
    assert aggregate.get_all()[0].description == "SMB signing disabled"


def test_run_module_without_findings_manager_does_not_error():
    """findings_manager is optional — omitting it (the pre-Phase-9-F
    default) must not raise."""
    from core.workflow_orchestrator import _run_module

    fake_module = MagicMock()
    fake_module.run.return_value = {"phases": {}}
    fake_module.loot = MagicMock()

    with patch("modules.network.network_module.NetworkModule", return_value=fake_module):
        result = _run_module("network", "10.10.10.1")

    assert result == {"phases": {}}


@patch("modules.network.network_module.OutputManager")
def test_workflow_orchestrator_handoff_to_out_of_scope_target_fails_step_not_workflow(mock_om):
    """A workflow-level scope should cause an out-of-scope auto-handoff step
    to fail cleanly (recorded as a failed, non-critical step) rather than
    silently scanning outside the engagement or crashing the whole run.

    Only OutputManager is mocked (to avoid touching disk) — NetworkModule's
    real __init__ runs, so this exercises the real Runner scope check, not a
    mocked module that would bypass it.
    """
    from core.workflow_orchestrator import WorkflowOrchestrator

    scope = _make_scope(["10.10.10.1"])  # does NOT include 10.10.10.99
    wf = WorkflowOrchestrator(targets=["10.10.10.1"], dry_run=False, scope=scope,
                               approval_id="APPROVAL-1")
    wf.add_step("network")

    # Force this step's target to one outside the configured scope, as if
    # discovered mid-workflow (e.g. via auto-handoff) rather than the
    # originally authorized target.
    wf._pick_target = MagicMock(return_value="10.10.10.99")

    summary = wf.run()

    assert summary["steps_failed"] >= 1
    failed = [r for r in wf._results if r.status == "failed"]
    assert failed and "not present in allowed_targets" in (failed[0].error or "")
