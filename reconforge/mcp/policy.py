"""Execution-tier policy classification for controlled MCP execution.

Three MCP tools call into this module: ``reconforge_request_execution``
(creates a pending, out-of-band approval request — see
``reconforge/mcp/approvals.py``), and ``reconforge_execute_approved_phase``/
``reconforge_start_execution`` (which only ever run an operation whose
approval request has already been consumed). Nothing in this module
executes anything itself — it only classifies a ``(module, phase)``
pair into a tier and evaluates whether the information a caller
supplies satisfies that tier's requirements.

The critical invariant enforced by :func:`evaluate`: it never grants
approval on its own. ``has_operator_approval`` is a required *input*
the caller must have obtained by consuming a genuinely
operator-approved :class:`reconforge.mcp.approvals.ApprovalRequest`
(never derived, defaulted, or inferred by this function) — the model
cannot talk its way past this by choosing what arguments to pass,
because :func:`evaluate` treats an absent value as exactly that:
absent, and nothing in the MCP tool surface lets a client set
``approvals.ApprovalRequest.status`` to ``"approved"`` — only a human
running ``reconforge mcp approvals approve`` in a separate process can.
See :func:`evaluate`'s docstring and
``tests/mcp/test_policy.py::test_evaluate_never_self_approves``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ExecutionTier(str, Enum):
    """SAFE_READ_ONLY is the least restrictive; PROHIBITED is never reachable
    through any MCP tool (enforced by omission, not a runtime check — see
    docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md §4's "concretely blocked by
    design" list). It exists here only to document that the taxonomy has a
    ceiling, and every classification in this module returns something else.
    """

    SAFE_READ_ONLY = "safe_read_only"
    LOW_IMPACT = "low_impact"
    ACTIVE_RECON = "active_recon"
    INTRUSIVE = "intrusive"
    CREDENTIAL_USE = "credential_use"
    PROHIBITED = "prohibited"


# (module, phase) -> tier. Cross-referenced against the real opt-in gates
# and phase semantics confirmed while building reconforge/mcp/services.py's
# module introspection (Phase 3), not invented:
#   - network's "authentication" phase runs non-invasive checks by default;
#     hydra brute-forcing only runs when the separate brute_force=True
#     parameter is set (see classify_phase below) — the phase itself is
#     ACTIVE_RECON, brute_force=True is what elevates it to CREDENTIAL_USE.
#   - web's "exploit" phase and api's "authorization" phase both require
#     opt_in=True in the real module code (exploit-candidate detection /
#     authorization testing, not automatic exploitation).
#   - ad's "delegation"/"bloodhound" phases have no code-level opt-in gate
#     (ADModule.__init__ accepts username/password unconditionally), but
#     their entire purpose is credentialed collection — classified
#     CREDENTIAL_USE as the conservative, honest default rather than
#     ACTIVE_RECON just because there's no boolean flag to key off.
#   - surface's "vector_correlation"/"prioritization" phases only
#     correlate/rank data already collected by earlier phases in the same
#     run — no new scan, no new network traffic — hence SAFE_READ_ONLY.
_PHASE_TIERS: dict[tuple[str, str], ExecutionTier] = {
    ("network", "discovery"): ExecutionTier.ACTIVE_RECON,
    ("network", "scanning"): ExecutionTier.ACTIVE_RECON,
    ("network", "enumeration"): ExecutionTier.ACTIVE_RECON,
    ("network", "authentication"): ExecutionTier.ACTIVE_RECON,
    ("ad", "passive"): ExecutionTier.ACTIVE_RECON,
    ("ad", "identity"): ExecutionTier.ACTIVE_RECON,
    ("ad", "configuration"): ExecutionTier.ACTIVE_RECON,
    ("ad", "delegation"): ExecutionTier.CREDENTIAL_USE,
    ("ad", "bloodhound"): ExecutionTier.CREDENTIAL_USE,
    ("web", "surface"): ExecutionTier.ACTIVE_RECON,
    ("web", "content"): ExecutionTier.ACTIVE_RECON,
    ("web", "vuln"): ExecutionTier.ACTIVE_RECON,
    ("web", "exploit"): ExecutionTier.INTRUSIVE,
    ("api", "discovery"): ExecutionTier.ACTIVE_RECON,
    ("api", "authentication"): ExecutionTier.ACTIVE_RECON,
    ("api", "fuzzing"): ExecutionTier.ACTIVE_RECON,
    ("api", "authorization"): ExecutionTier.INTRUSIVE,
    ("surface", "port_discovery"): ExecutionTier.ACTIVE_RECON,
    ("surface", "service_fingerprint"): ExecutionTier.ACTIVE_RECON,
    ("surface", "vector_correlation"): ExecutionTier.SAFE_READ_ONLY,
    ("surface", "prioritization"): ExecutionTier.SAFE_READ_ONLY,
}


def classify_phase(module: str, phase: str, module_parameters: dict[str, object] | None = None) -> ExecutionTier:
    """Classify a ``(module, phase)`` pair, elevated by known parameter gates.

    An unrecognized ``(module, phase)`` combination defaults to
    ``ACTIVE_RECON`` — a genuine scan against a real target should never
    silently fall back to the least-restrictive tier just because it's
    unrecognized.
    """
    tier = _PHASE_TIERS.get((module, phase), ExecutionTier.ACTIVE_RECON)

    params = module_parameters or {}
    if module == "network" and phase == "authentication" and params.get("brute_force") is True:
        return ExecutionTier.CREDENTIAL_USE

    return tier


@dataclass(frozen=True)
class TierRequirements:
    allowed_by_default: bool
    requires_engagement: bool
    requires_scope: bool
    requires_operator_approval: bool


_TIER_REQUIREMENTS: dict[ExecutionTier, TierRequirements] = {
    ExecutionTier.SAFE_READ_ONLY: TierRequirements(True, False, False, False),
    ExecutionTier.LOW_IMPACT: TierRequirements(True, True, True, False),
    ExecutionTier.ACTIVE_RECON: TierRequirements(True, True, True, True),
    # allowed_by_default=True here means "reachable if every requirement is
    # met" — evaluate()'s intrusive_execution_allowed parameter adds a
    # further, server-wide off switch on top of these per-request
    # requirements (config/mcp.yaml's mcp.allow_intrusive_execution, off
    # by default — see services.py::_intrusive_execution_allowed()).
    ExecutionTier.INTRUSIVE: TierRequirements(True, True, True, True),
    ExecutionTier.CREDENTIAL_USE: TierRequirements(True, True, True, True),
    ExecutionTier.PROHIBITED: TierRequirements(False, True, True, True),
}


def requirements_for(tier: ExecutionTier) -> TierRequirements:
    return _TIER_REQUIREMENTS[tier]


@dataclass(frozen=True)
class PolicyDecision:
    tier: ExecutionTier
    allowed: bool
    missing_requirements: tuple[str, ...]
    reason: str


def evaluate(
    tier: ExecutionTier,
    *,
    has_engagement: bool = False,
    has_validated_scope: bool = False,
    has_operator_approval: bool = False,
    intrusive_execution_allowed: bool = False,
) -> PolicyDecision:
    """Decide whether *tier*'s requirements are satisfied by the given facts.

    Every keyword argument defaults to the *denying* value
    (``False``) — a caller that forgets to pass one gets a rejection,
    not an accidental approval. This function never sets
    ``has_operator_approval`` itself; it must originate from a
    successful ``reconforge/mcp/approvals.py::consume_if_approved()``
    call — proof a human ran ``reconforge mcp approvals approve`` in a
    process outside the MCP protocol entirely, not merely that an MCP
    request included a particular field. ``intrusive_execution_allowed``
    is likewise never derived from the request — it comes only from
    ``config/mcp.yaml``'s ``mcp.allow_intrusive_execution`` (a
    server-wide, operator-controlled setting a single MCP request cannot
    influence), read by the caller before invoking this function.
    """
    if tier is ExecutionTier.PROHIBITED:
        return PolicyDecision(
            tier=tier,
            allowed=False,
            missing_requirements=(),
            reason="PROHIBITED-tier actions are never exposed through MCP.",
        )

    reqs = _TIER_REQUIREMENTS[tier]
    missing: list[str] = []

    if reqs.requires_engagement and not has_engagement:
        missing.append("engagement_id")
    if reqs.requires_scope and not has_validated_scope:
        missing.append("validated scope (scope_file + target in allowed_targets)")
    if reqs.requires_operator_approval and not has_operator_approval:
        missing.append("operator approval (see 'reconforge mcp approvals approve')")
    if tier is ExecutionTier.INTRUSIVE and not intrusive_execution_allowed:
        missing.append("mcp.allow_intrusive_execution=true in config/mcp.yaml (server-wide, operator-controlled)")

    allowed = not missing
    reason = "all tier requirements satisfied" if allowed else f"missing: {', '.join(missing)}"
    return PolicyDecision(tier=tier, allowed=allowed, missing_requirements=tuple(missing), reason=reason)
