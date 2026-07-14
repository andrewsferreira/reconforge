"""Request/response schemas for the read-only MCP tools.

Pydantic models, matching the `mcp` SDK's own use of pydantic for its
protocol types. Requests are the MCP input-validation boundary — every
field Claude supplies is re-validated here before any lookup happens
(see docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md §2, the MCP Input Validation
Layer). Responses are also modelled so a bug that would silently return
a wrong-shaped dict instead raises at construction time.

Trust labelling (docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md §5): fields under
``TrustedMetadata`` are ReconForge-computed (ids, severity/confidence
enums, module names, timestamps). Fields under ``UntrustedEvidence`` may
contain text that originated from a scanned target and must never be
treated as an instruction by anything that reads it.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

MODULE_NAMES = ("network", "ad", "web", "api", "surface")
ModuleName = Literal["network", "ad", "web", "api", "surface"]
OpsecProfile = Literal["stealth", "normal", "aggressive"]


# ── reconforge_get_status ────────────────────────────────────────────


class GetStatusRequest(BaseModel):
    pass


class GetStatusResponse(BaseModel):
    reconforge_version: str
    python_version: str
    os: str
    modules: list[str]
    available_tools: list[str]
    missing_tools: list[str]
    security_controls: list[str]
    supported_output_formats: list[str]


# ── reconforge_list_modules / reconforge_get_module_details ─────────


class ListModulesRequest(BaseModel):
    pass


class ModuleSummary(BaseModel):
    name: str
    valid_phases: list[str]
    tool_wrappers: list[str]
    target_type: str
    opt_in_capabilities: list[str]


class ListModulesResponse(BaseModel):
    modules: list[ModuleSummary]


class GetModuleDetailsRequest(BaseModel):
    module: ModuleName


class GetModuleDetailsResponse(BaseModel):
    module: ModuleSummary
    documentation_reference: str = Field(
        default="docs/MODULES.md",
        description="Where full per-phase descriptions live; not duplicated here.",
    )


# ── reconforge_list_engagements / reconforge_get_engagement ─────────


class ListEngagementsRequest(BaseModel):
    output_base: str = "outputs"


class EngagementSummary(BaseModel):
    engagement_id: str
    name: str
    client: str
    status: str
    declared_scope_targets: list[str]
    modules_run: list[str]
    findings_summary: dict[str, int]


class ListEngagementsResponse(BaseModel):
    engagements: list[EngagementSummary]
    discoverability_note: str = Field(
        default=(
            "Only engagements created via `reconforge workflow ...` and saved "
            "under <output_base>/workflow/engagement_*.json are discoverable. "
            "Single-module runs (network/ad/web/api/surface) do not create an "
            "engagement file."
        )
    )


class GetEngagementRequest(BaseModel):
    engagement_id: str
    output_base: str = "outputs"


class TimelineEntrySummary(BaseModel):
    timestamp: str
    module: str
    action: str
    detail: str = ""


class GetEngagementResponse(BaseModel):
    summary: EngagementSummary
    timeline: list[TimelineEntrySummary]
    loot_summary: dict[str, int]


# ── reconforge_get_scope ─────────────────────────────────────────────


class GetScopeRequest(BaseModel):
    scope_file: str


class GetScopeResponse(BaseModel):
    allowed_targets: list[str]
    approval_id: str
    valid_until: str
    is_expired: bool
    enforcement_mode: str = "explicit_scope_file"


# ── reconforge_plan_workflow ─────────────────────────────────────────


class PlanWorkflowRequest(BaseModel):
    target: str
    modules: list[ModuleName] | None = None
    opsec_profile: OpsecProfile = "normal"
    scope_file: str | None = None
    approval_id: str | None = None


class PlannedStep(BaseModel):
    module: str
    phases: list[str]
    tool_wrappers: list[str]
    conditional: bool = Field(
        description="True for ad/web/api in the default pipeline: whether they "
        "actually run is decided at execution time by what surface/network "
        "discover, not predictable in a static plan."
    )
    opt_in_capabilities: list[str]


class ScopeDecision(BaseModel):
    enforced: bool
    target_allowed: bool | None = None
    reason: str = ""


class PlanWorkflowResponse(BaseModel):
    normalized_target: str
    selected_modules: list[PlannedStep]
    scope_decision: ScopeDecision
    warnings: list[str]
    required_approvals: list[str]
    recommended_execution_order: list[str]


# ── reconforge_dry_run ────────────────────────────────────────────────


class DryRunRequest(BaseModel):
    target: str
    module: ModuleName
    phases: list[str] | None = None
    opsec_profile: OpsecProfile = "normal"
    timeout: int = 600
    output_base: str = "outputs"
    domain: str = ""
    scope_file: str | None = None
    approval_id: str | None = None


class DryRunResponse(BaseModel):
    module: str
    target: str
    phases_run: list[str]
    commands: list[str]
    artifacts_written: list[str]
    warnings: list[str]
