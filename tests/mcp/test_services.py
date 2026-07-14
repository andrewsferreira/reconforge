"""Unit tests for reconforge/mcp/services.py — the read-only MCP tools'
implementation, exercised directly (no MCP protocol layer involved).

These assert against real ReconForge primitives, not mocks: module
classes are imported for real, engagement files are real
EngagementManager.save() output, scope files are real YAML parsed by
ScopeAuthorization.from_file(), and the dry-run test proves — by making
subprocess.run raise if called — that dry-run genuinely never executes
anything, not just that it returns success.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from core.engagement import EngagementManager
from reconforge.mcp import schemas, services
from reconforge.mcp.errors import (
    EngagementNotFoundError,
    InvalidMCPRequestError,
    ScopeFileError,
    UnknownPhaseError,
)


# ── reconforge_get_status ────────────────────────────────────────────


def test_get_status_reports_reconforge_version_and_all_five_modules():
    from core.version import __version__

    response = services.get_status(schemas.GetStatusRequest())
    assert response.reconforge_version == __version__
    assert set(response.modules) == set(schemas.MODULE_NAMES)
    assert set(response.available_tools).isdisjoint(response.missing_tools)
    assert "json" in response.supported_output_formats
    assert "markdown" in response.supported_output_formats


def test_get_status_never_exposes_environment_variables():
    response = services.get_status(schemas.GetStatusRequest())
    dumped = response.model_dump_json()
    assert "PATH=" not in dumped
    assert "HOME=" not in dumped


# ── reconforge_list_modules / reconforge_get_module_details ─────────


def test_list_modules_matches_each_module_classs_real_valid_phases():
    from modules.network.network_module import NetworkModule

    response = services.list_modules(schemas.ListModulesRequest())
    names = {m.name for m in response.modules}
    assert names == set(schemas.MODULE_NAMES)

    network = next(m for m in response.modules if m.name == "network")
    assert network.valid_phases == list(NetworkModule.VALID_PHASES)
    assert "nmap" in network.tool_wrappers


def test_get_module_details_for_network_flags_hydra_as_opt_in():
    response = services.get_module_details(schemas.GetModuleDetailsRequest(module="network"))
    assert response.module.name == "network"
    assert any("hydra" in cap for cap in response.module.opt_in_capabilities)


def test_get_module_details_for_ad_has_no_opt_in_capabilities():
    response = services.get_module_details(schemas.GetModuleDetailsRequest(module="ad"))
    assert response.module.opt_in_capabilities == []


# ── reconforge_list_engagements / reconforge_get_engagement ─────────


def test_list_engagements_returns_empty_list_when_no_workflow_dir(tmp_path: Path):
    response = services.list_engagements(schemas.ListEngagementsRequest(output_base=str(tmp_path)))
    assert response.engagements == []


def _save_test_engagement(tmp_path: Path, engagement_id: str = "engagement_test") -> None:
    mgr = EngagementManager(name="Q1 Pentest", client="Acme", operator="tester", scope=["10.10.10.1"])
    mgr.start()
    mgr.record_action("network", "step_started", detail="Target: 10.10.10.1")
    mgr.record_module_result("network", {"phases": {}})
    workflow_dir = tmp_path / "workflow"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    mgr.save(workflow_dir / f"{engagement_id}.json")


def test_list_engagements_and_get_engagement_round_trip(tmp_path: Path):
    _save_test_engagement(tmp_path)

    listed = services.list_engagements(schemas.ListEngagementsRequest(output_base=str(tmp_path)))
    assert len(listed.engagements) == 1
    assert listed.engagements[0].name == "Q1 Pentest"
    assert listed.engagements[0].declared_scope_targets == ["10.10.10.1"]
    assert listed.engagements[0].modules_run == ["network"]

    fetched = services.get_engagement(
        schemas.GetEngagementRequest(engagement_id="engagement_test", output_base=str(tmp_path))
    )
    assert fetched.summary.name == "Q1 Pentest"
    assert fetched.summary.status == "active"
    assert any(entry.action == "step_started" for entry in fetched.timeline)


def test_get_engagement_raises_not_found_for_unknown_id(tmp_path: Path):
    with pytest.raises(EngagementNotFoundError):
        services.get_engagement(
            schemas.GetEngagementRequest(engagement_id="does_not_exist", output_base=str(tmp_path))
        )


def test_list_engagements_skips_corrupt_files_instead_of_failing(tmp_path: Path):
    workflow_dir = tmp_path / "workflow"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    (workflow_dir / "engagement_corrupt.json").write_text("{not valid json")
    _save_test_engagement(tmp_path, engagement_id="engagement_good")

    response = services.list_engagements(schemas.ListEngagementsRequest(output_base=str(tmp_path)))
    assert len(response.engagements) == 1
    assert response.engagements[0].engagement_id == "engagement_good"


# ── reconforge_get_scope ─────────────────────────────────────────────


def _write_scope_file(path: Path, valid_until: datetime, targets=("10.10.10.1",)) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "allowed_targets": list(targets),
                "approval_id": "APPROVAL-1",
                "valid_until": valid_until.isoformat(),
            }
        )
    )


def test_get_scope_reads_allowed_targets_and_is_not_expired(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"
    _write_scope_file(scope_file, datetime.now(timezone.utc) + timedelta(days=1))

    response = services.get_scope(schemas.GetScopeRequest(scope_file=str(scope_file)))
    assert response.allowed_targets == ["10.10.10.1"]
    assert response.approval_id == "APPROVAL-1"
    assert response.is_expired is False


def test_get_scope_flags_expired_scope(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"
    _write_scope_file(scope_file, datetime.now(timezone.utc) - timedelta(days=1))

    response = services.get_scope(schemas.GetScopeRequest(scope_file=str(scope_file)))
    assert response.is_expired is True


def test_get_scope_raises_for_missing_file(tmp_path: Path):
    with pytest.raises(ScopeFileError):
        services.get_scope(schemas.GetScopeRequest(scope_file=str(tmp_path / "nope.yaml")))


# ── reconforge_plan_workflow ─────────────────────────────────────────


def test_plan_workflow_default_pipeline_flags_ad_web_api_as_conditional():
    response = services.plan_workflow(schemas.PlanWorkflowRequest(target="10.10.10.1"))
    by_module = {s.module: s for s in response.selected_modules}
    assert by_module["surface"].conditional is False
    assert by_module["network"].conditional is False
    assert by_module["ad"].conditional is True
    assert by_module["web"].conditional is True
    assert by_module["api"].conditional is True
    assert response.recommended_execution_order == ["surface", "network", "ad", "web", "api"]


def test_plan_workflow_explicit_modules_are_not_conditional():
    response = services.plan_workflow(schemas.PlanWorkflowRequest(target="10.10.10.1", modules=["web"]))
    assert len(response.selected_modules) == 1
    assert response.selected_modules[0].conditional is False


def test_plan_workflow_warns_when_no_scope_file_given():
    response = services.plan_workflow(schemas.PlanWorkflowRequest(target="10.10.10.1"))
    assert response.scope_decision.enforced is False
    assert any("scope" in w.lower() for w in response.warnings)


def test_plan_workflow_validates_target_against_scope_file(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"
    _write_scope_file(scope_file, datetime.now(timezone.utc) + timedelta(days=1), targets=("10.10.10.1",))

    allowed = services.plan_workflow(
        schemas.PlanWorkflowRequest(target="10.10.10.1", scope_file=str(scope_file))
    )
    assert allowed.scope_decision.enforced is True
    assert allowed.scope_decision.target_allowed is True

    disallowed = services.plan_workflow(
        schemas.PlanWorkflowRequest(target="10.10.10.99", scope_file=str(scope_file))
    )
    assert disallowed.scope_decision.target_allowed is False
    assert any("not in the scope file" in w for w in disallowed.warnings)


def test_plan_workflow_rejects_invalid_target():
    with pytest.raises(InvalidMCPRequestError):
        services.plan_workflow(schemas.PlanWorkflowRequest(target="10.10.10.1; rm -rf /"))


# ── reconforge_dry_run ────────────────────────────────────────────────


def test_dry_run_never_calls_subprocess(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def _fail_if_called(*args, **kwargs):
        raise AssertionError("dry_run must never call subprocess.run")

    monkeypatch.setattr(subprocess, "run", _fail_if_called)

    response = services.dry_run(
        schemas.DryRunRequest(
            target="10.10.10.1",
            module="network",
            phases=["discovery"],
            output_base=str(tmp_path),
        )
    )
    assert response.module == "network"
    assert response.phases_run == ["discovery"]
    assert Path(response.artifacts_written[0]).is_dir()


def test_dry_run_rejects_unknown_phase(tmp_path: Path):
    with pytest.raises(UnknownPhaseError):
        services.dry_run(
            schemas.DryRunRequest(
                target="10.10.10.1",
                module="network",
                phases=["not_a_real_phase"],
                output_base=str(tmp_path),
            )
        )


def test_dry_run_rejects_invalid_target(tmp_path: Path):
    with pytest.raises(InvalidMCPRequestError):
        services.dry_run(
            schemas.DryRunRequest(
                target="10.10.10.1; rm -rf /",
                module="network",
                output_base=str(tmp_path),
            )
        )


def test_dry_run_accepts_a_web_target_with_a_non_default_port(tmp_path: Path):
    """Regression test: dry_run used to validate every module's target
    with parse_target() (bare IP/CIDR/hostname only), which rejects a
    "host:port" string outright — even though WebModule/APIModule's own
    _normalise_url() accepts exactly this shape. Found while building
    the lab.vulnerable_app.py integration test (MCP Phase 11)."""
    response = services.dry_run(
        schemas.DryRunRequest(
            target="127.0.0.1:8899",
            module="web",
            phases=["surface"],
            output_base=str(tmp_path),
        )
    )
    assert response.module == "web"
    assert response.target == "127.0.0.1:8899"
    assert any("127.0.0.1:8899" in command for command in response.commands)


def test_dry_run_rejects_a_web_target_containing_shell_metacharacters(tmp_path: Path):
    """validate_url() alone only checks scheme/netloc/userinfo, not shell
    metacharacters — this proves the web/api path still rejects them at
    the MCP boundary, with the same immediate, clear error every other
    module's target already gets from parse_target()."""
    with pytest.raises(InvalidMCPRequestError):
        services.dry_run(
            schemas.DryRunRequest(
                target="127.0.0.1:8899; rm -rf /",
                module="web",
                output_base=str(tmp_path),
            )
        )


def test_dry_run_rejects_a_web_target_with_embedded_userinfo_credentials(tmp_path: Path):
    """Distinct branch from the shell-metacharacter test above: this one
    has no shell metacharacters at all, so it can only be caught by
    validate_url()'s own embedded-userinfo check, not validate_arg()."""
    with pytest.raises(InvalidMCPRequestError):
        services.dry_run(
            schemas.DryRunRequest(
                target="user:pass@127.0.0.1",
                module="web",
                output_base=str(tmp_path),
            )
        )
