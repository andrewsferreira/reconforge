"""Tests for reconforge/mcp/policy.py — the SAFE_READ_ONLY -> PROHIBITED
execution-tier classification and requirement evaluation.

No execution tool exists yet; this only tests the policy layer those
tools will be built on. The most important test in this file is
test_evaluate_never_self_approves, which pins down the one invariant
that makes controlled execution safe to build on top of later: this
module never manufactures approval on its own.
"""

from __future__ import annotations

import pytest

from reconforge.mcp import schemas, services
from reconforge.mcp.policy import (
    ExecutionTier,
    classify_phase,
    evaluate,
    requirements_for,
)


# ── classify_phase ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "module,phase,expected",
    [
        ("network", "discovery", ExecutionTier.ACTIVE_RECON),
        ("network", "scanning", ExecutionTier.ACTIVE_RECON),
        ("network", "enumeration", ExecutionTier.ACTIVE_RECON),
        ("network", "authentication", ExecutionTier.ACTIVE_RECON),
        ("ad", "passive", ExecutionTier.ACTIVE_RECON),
        ("ad", "identity", ExecutionTier.ACTIVE_RECON),
        ("ad", "configuration", ExecutionTier.ACTIVE_RECON),
        ("ad", "delegation", ExecutionTier.CREDENTIAL_USE),
        ("ad", "bloodhound", ExecutionTier.CREDENTIAL_USE),
        ("web", "surface", ExecutionTier.ACTIVE_RECON),
        ("web", "content", ExecutionTier.ACTIVE_RECON),
        ("web", "vuln", ExecutionTier.ACTIVE_RECON),
        ("web", "exploit", ExecutionTier.INTRUSIVE),
        ("api", "discovery", ExecutionTier.ACTIVE_RECON),
        ("api", "authentication", ExecutionTier.ACTIVE_RECON),
        ("api", "fuzzing", ExecutionTier.ACTIVE_RECON),
        ("api", "authorization", ExecutionTier.INTRUSIVE),
        ("surface", "port_discovery", ExecutionTier.ACTIVE_RECON),
        ("surface", "service_fingerprint", ExecutionTier.ACTIVE_RECON),
        ("surface", "vector_correlation", ExecutionTier.SAFE_READ_ONLY),
        ("surface", "prioritization", ExecutionTier.SAFE_READ_ONLY),
    ],
)
def test_classify_phase_matches_documented_tier_for_every_known_phase(module, phase, expected):
    assert classify_phase(module, phase) == expected


def test_classify_phase_unknown_combination_defaults_to_active_recon_not_safe():
    assert classify_phase("network", "not_a_real_phase") == ExecutionTier.ACTIVE_RECON
    assert classify_phase("not_a_real_module", "discovery") == ExecutionTier.ACTIVE_RECON


def test_classify_network_authentication_elevates_to_credential_use_with_brute_force():
    tier = classify_phase("network", "authentication", module_parameters={"brute_force": True})
    assert tier == ExecutionTier.CREDENTIAL_USE


def test_classify_network_authentication_stays_active_recon_without_brute_force():
    assert classify_phase("network", "authentication", module_parameters={"brute_force": False}) == ExecutionTier.ACTIVE_RECON
    assert classify_phase("network", "authentication", module_parameters=None) == ExecutionTier.ACTIVE_RECON
    assert classify_phase("network", "authentication", module_parameters={}) == ExecutionTier.ACTIVE_RECON


def test_brute_force_parameter_only_elevates_the_network_authentication_phase():
    """The brute_force gate is specific to network/authentication — passing
    it for an unrelated module/phase must not silently elevate that too."""
    tier = classify_phase("web", "content", module_parameters={"brute_force": True})
    assert tier == ExecutionTier.ACTIVE_RECON


# ── requirements_for ─────────────────────────────────────────────────


def test_safe_read_only_requires_nothing():
    reqs = requirements_for(ExecutionTier.SAFE_READ_ONLY)
    assert reqs.requires_engagement is False
    assert reqs.requires_scope is False
    assert reqs.requires_explicit_confirmation is False
    assert reqs.requires_approval_id is False


def test_active_recon_requires_engagement_scope_and_confirmation_but_not_approval_id():
    reqs = requirements_for(ExecutionTier.ACTIVE_RECON)
    assert reqs.requires_engagement is True
    assert reqs.requires_scope is True
    assert reqs.requires_explicit_confirmation is True
    assert reqs.requires_approval_id is False


@pytest.mark.parametrize("tier", [ExecutionTier.INTRUSIVE, ExecutionTier.CREDENTIAL_USE])
def test_intrusive_and_credential_use_require_approval_id_too(tier):
    reqs = requirements_for(tier)
    assert reqs.requires_approval_id is True
    assert reqs.requires_explicit_confirmation is True


def test_prohibited_is_not_allowed_by_default():
    assert requirements_for(ExecutionTier.PROHIBITED).allowed_by_default is False


# ── evaluate ─────────────────────────────────────────────────────────


def test_evaluate_safe_read_only_always_allowed_with_no_arguments():
    decision = evaluate(ExecutionTier.SAFE_READ_ONLY)
    assert decision.allowed is True
    assert decision.missing_requirements == ()


def test_evaluate_active_recon_denied_when_nothing_supplied():
    decision = evaluate(ExecutionTier.ACTIVE_RECON)
    assert decision.allowed is False
    assert "engagement_id" in decision.missing_requirements
    assert "explicit_confirmation=true" in decision.missing_requirements


def test_evaluate_active_recon_allowed_when_all_requirements_met():
    decision = evaluate(
        ExecutionTier.ACTIVE_RECON,
        has_engagement=True,
        has_validated_scope=True,
        explicit_confirmation=True,
    )
    assert decision.allowed is True
    assert decision.missing_requirements == ()


def test_evaluate_active_recon_denied_without_confirmation_even_with_everything_else_true():
    decision = evaluate(
        ExecutionTier.ACTIVE_RECON,
        has_engagement=True,
        has_validated_scope=True,
        explicit_confirmation=False,
        approval_id="whatever-not-required-here",
    )
    assert decision.allowed is False
    assert decision.missing_requirements == ("explicit_confirmation=true",)


@pytest.mark.parametrize("tier", [ExecutionTier.INTRUSIVE, ExecutionTier.CREDENTIAL_USE])
def test_evaluate_intrusive_and_credential_use_denied_without_approval_id(tier):
    decision = evaluate(
        tier,
        has_engagement=True,
        has_validated_scope=True,
        explicit_confirmation=True,
        approval_id=None,
    )
    assert decision.allowed is False
    assert "approval_id" in decision.missing_requirements


def test_evaluate_credential_use_allowed_with_full_approval():
    decision = evaluate(
        ExecutionTier.CREDENTIAL_USE,
        has_engagement=True,
        has_validated_scope=True,
        explicit_confirmation=True,
        approval_id="APPROVAL-123",
    )
    assert decision.allowed is True


def test_evaluate_intrusive_denied_without_config_gate_even_with_full_approval():
    """INTRUSIVE has an extra server-wide off switch
    (mcp.allow_intrusive_execution in config/mcp.yaml, defaults to false)
    that per-request approval alone can't satisfy — an operator has to
    opt the whole server in, not just approve one request."""
    decision = evaluate(
        ExecutionTier.INTRUSIVE,
        has_engagement=True,
        has_validated_scope=True,
        explicit_confirmation=True,
        approval_id="APPROVAL-123",
    )
    assert decision.allowed is False
    assert any("allow_intrusive_execution" in m for m in decision.missing_requirements)


def test_evaluate_intrusive_allowed_with_full_approval_and_config_gate_enabled():
    decision = evaluate(
        ExecutionTier.INTRUSIVE,
        has_engagement=True,
        has_validated_scope=True,
        explicit_confirmation=True,
        approval_id="APPROVAL-123",
        intrusive_execution_allowed=True,
    )
    assert decision.allowed is True


def test_evaluate_empty_string_approval_id_counts_as_missing():
    decision = evaluate(
        ExecutionTier.INTRUSIVE,
        has_engagement=True,
        has_validated_scope=True,
        explicit_confirmation=True,
        approval_id="",
    )
    assert decision.allowed is False
    assert "approval_id" in decision.missing_requirements


def test_evaluate_prohibited_is_never_allowed_regardless_of_inputs():
    """The one tier this project's own working spec says must never be
    reachable through MCP — confirmed even when every other input is set
    to the most permissive value possible."""
    decision = evaluate(
        ExecutionTier.PROHIBITED,
        has_engagement=True,
        has_validated_scope=True,
        explicit_confirmation=True,
        approval_id="APPROVAL-123",
    )
    assert decision.allowed is False


# ── integration: reconforge_plan_workflow surfaces the real tiers ────


def test_plan_workflow_surfaces_phase_tiers_for_every_planned_phase():
    response = services.plan_workflow(schemas.PlanWorkflowRequest(target="10.10.10.1", modules=["web"]))
    step = response.selected_modules[0]
    assert step.phase_tiers["surface"] == ExecutionTier.ACTIVE_RECON.value
    assert step.phase_tiers["exploit"] == ExecutionTier.INTRUSIVE.value


def test_plan_workflow_required_approvals_reflects_intrusive_and_credential_use_phases():
    response = services.plan_workflow(schemas.PlanWorkflowRequest(target="10.10.10.1"))
    approvals_text = " ".join(response.required_approvals)
    assert "web: exploit" in approvals_text
    assert "api: authorization" in approvals_text
    assert "ad: delegation" in approvals_text or "ad: bloodhound" in approvals_text


def test_evaluate_never_self_approves():
    """The core safety invariant: calling evaluate() with its defaults
    (i.e., as if a caller simply forgot to pass explicit_confirmation/
    approval_id) must deny every tier above SAFE_READ_ONLY — this
    function has no internal path that manufactures approval on its own,
    only one that checks values the caller must have obtained from the
    operator."""
    for tier in (
        ExecutionTier.LOW_IMPACT,
        ExecutionTier.ACTIVE_RECON,
        ExecutionTier.INTRUSIVE,
        ExecutionTier.CREDENTIAL_USE,
    ):
        decision = evaluate(tier)
        assert decision.allowed is False, f"{tier} was allowed with no supplied facts"
