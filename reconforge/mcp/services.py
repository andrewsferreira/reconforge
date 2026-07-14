"""Service layer for the read-only MCP tools.

Plain functions with no dependency on the ``mcp`` SDK — this module can
be (and is, in tests) exercised directly. Every function wraps an
existing ReconForge primitive rather than re-implementing it: module
introspection reads each module class's own ``MODULE_NAME``/
``VALID_PHASES``; scope reads reuse
``core.authorization_gate.ScopeAuthorization``; dry-run instantiates the
real module classes with ``dry_run=True`` and reads back
``Runner.get_command_log()`` (already secret-redacted at the point it's
appended — see ``core/runner.py``); engagement/scope data is read
straight off disk in the same layout the CLI itself writes.
"""

from __future__ import annotations

import importlib
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import modules

from core.authorization_gate import ScopeAuthorization
from core.config_loader import ConfigLoader
from core.engagement import EngagementManager
from core.exceptions import EngagementError
from core.exceptions import EngagementNotFoundError as CoreEngagementNotFoundError
from core.exceptions import ReconForgeError, TargetValidationError
from core.target_parser import parse_target
from core.version import __version__ as RECONFORGE_VERSION

from reconforge.mcp.errors import (
    EngagementNotFoundError,
    InvalidMCPRequestError,
    ScopeFileError,
    UnknownPhaseError,
)
from reconforge.mcp.schemas import (
    MODULE_NAMES,
    DryRunRequest,
    DryRunResponse,
    EngagementSummary,
    GetEngagementRequest,
    GetEngagementResponse,
    GetModuleDetailsRequest,
    GetModuleDetailsResponse,
    GetScopeRequest,
    GetScopeResponse,
    GetStatusRequest,
    GetStatusResponse,
    ListEngagementsRequest,
    ListEngagementsResponse,
    ListModulesRequest,
    ListModulesResponse,
    ModuleSummary,
    PlannedStep,
    PlanWorkflowRequest,
    PlanWorkflowResponse,
    ScopeDecision,
    TimelineEntrySummary,
)

_MODULES_DIR = Path(modules.__file__).resolve().parent

_MODULE_CLASS_PATHS = {
    "network": ("modules.network.network_module", "NetworkModule"),
    "ad": ("modules.ad.ad_module", "ADModule"),
    "web": ("modules.web.web_module", "WebModule"),
    "api": ("modules.api.api_module", "APIModule"),
    "surface": ("modules.surface.surface_module", "SurfaceModule"),
}

_MODULE_TARGET_TYPES = {
    "network": "IP address, hostname, or CIDR range",
    "ad": "Domain Controller IP/hostname, plus an AD domain name",
    "web": "HTTP(S) URL",
    "api": "HTTP(S) API base URL",
    "surface": "IP address or hostname",
}

# Grounded in the actual opt_in-gated capabilities found in each module's
# run() signature (network's brute_force flag, web's exploit phase, api's
# authorization phase) — ad and surface have no such gate today.
_MODULE_OPT_IN_CAPABILITIES: dict[str, tuple[str, ...]] = {
    "network": (
        "brute_force=True enables hydra password brute-forcing against "
        "discovered services (opt-in, off by default)",
    ),
    "web": (
        "the 'exploit' phase requires opt_in=True (exploit-candidate "
        "detection, not exploitation)",
    ),
    "api": (
        "the 'authorization' phase requires opt_in=True (authorization/BOLA "
        "testing)",
    ),
    "ad": (),
    "surface": (),
}

_SECURITY_CONTROLS = (
    "subprocess execution never uses shell=True (core/runner.py::Runner)",
    "shell-metacharacter argument validation (core/runner.py::validate_arg)",
    "child-process environment is an allowlist, not inherited wholesale "
    "(core/runner.py::Runner._ENV_ALLOWLIST)",
    "secrets are redacted from logs and command history before being "
    "written or returned (core/logger.py::sanitize_log)",
    "scope/approval enforcement via ScopeAuthorization when a scope file "
    "is supplied (core/authorization_gate.py)",
    "this MCP server is stdio-only; no network transport exists in this "
    "package",
    "this MCP server has no execution tools in this phase; read-only "
    "inspection only",
)

_DEFAULT_PIPELINE_ORDER = ("surface", "network", "ad", "web", "api")
_CONDITIONAL_MODULES = frozenset({"ad", "web", "api"})


def _module_class(name: str) -> Any:
    """Return one of the 5 module classes, looked up dynamically by name.

    Typed ``Any`` rather than a specific class: the 5 module classes
    (NetworkModule, ADModule, ...) share no common base class today, only
    a structural convention (``MODULE_NAME``, ``VALID_PHASES``, a
    constructor accepting the shared kwargs, ``.runner``/``.output``
    attributes after construction). A ``Protocol`` capturing that shape
    would be more precise but is unwarranted machinery for two call
    sites; ``Any`` here is a deliberate, narrow exception, not a broad
    escape hatch — every value derived from it below is immediately
    assigned into a typed pydantic field, which re-establishes strict
    typing at the boundary that matters.
    """
    module_path, class_name = _MODULE_CLASS_PATHS[name]
    mod = importlib.import_module(module_path)
    return getattr(mod, class_name)


def _tool_wrapper_names(module_name: str) -> list[str]:
    tools_dir = _MODULES_DIR / module_name / "tools"
    if not tools_dir.is_dir():
        return []
    return sorted(p.stem for p in tools_dir.glob("*.py") if p.stem != "__init__")


def _module_summary(name: str) -> ModuleSummary:
    cls = _module_class(name)
    return ModuleSummary(
        name=cls.MODULE_NAME,
        valid_phases=list(cls.VALID_PHASES),
        tool_wrappers=_tool_wrapper_names(name),
        target_type=_MODULE_TARGET_TYPES[name],
        opt_in_capabilities=list(_MODULE_OPT_IN_CAPABILITIES[name]),
    )


# ── reconforge_get_status ────────────────────────────────────────────


def get_status(_request: GetStatusRequest) -> GetStatusResponse:
    tools_cfg = ConfigLoader().load("tools").get("tools", {})
    available: list[str] = []
    missing: list[str] = []
    for tool_name, cfg in tools_cfg.items():
        candidates = [cfg.get("binary", tool_name)]
        for alt_key in ("alt_binary", "alt_binary2"):
            alt = cfg.get(alt_key)
            if alt:
                candidates.append(alt)
        found = any(shutil.which(c) for c in candidates if c)
        (available if found else missing).append(tool_name)

    return GetStatusResponse(
        reconforge_version=RECONFORGE_VERSION,
        python_version=platform.python_version(),
        os=f"{platform.system()} {platform.release()}",
        modules=list(MODULE_NAMES),
        available_tools=sorted(available),
        missing_tools=sorted(missing),
        security_controls=list(_SECURITY_CONTROLS),
        supported_output_formats=["json", "markdown"],
    )


# ── reconforge_list_modules / reconforge_get_module_details ─────────


def list_modules(_request: ListModulesRequest) -> ListModulesResponse:
    return ListModulesResponse(modules=[_module_summary(name) for name in MODULE_NAMES])


def get_module_details(request: GetModuleDetailsRequest) -> GetModuleDetailsResponse:
    return GetModuleDetailsResponse(module=_module_summary(request.module))


# ── reconforge_list_engagements / reconforge_get_engagement ─────────


def _engagement_dir(output_base: str) -> Path:
    return Path(output_base) / "workflow"


def _load_engagement_summary(path: Path) -> tuple[EngagementSummary, EngagementManager]:
    try:
        mgr = EngagementManager.load(path)
    except CoreEngagementNotFoundError as exc:
        raise EngagementNotFoundError(str(exc)) from exc
    except EngagementError as exc:
        raise EngagementNotFoundError(f"Engagement file is unreadable: {exc}") from exc

    summary = EngagementSummary(
        engagement_id=path.stem,
        name=mgr.meta.name,
        client=mgr.meta.client,
        status=mgr.status,
        declared_scope_targets=list(mgr.meta.scope),
        modules_run=list(mgr.modules_run),
        findings_summary=dict(mgr.findings_summary),
    )
    return summary, mgr


def list_engagements(request: ListEngagementsRequest) -> ListEngagementsResponse:
    directory = _engagement_dir(request.output_base)
    summaries: list[EngagementSummary] = []
    if directory.is_dir():
        for path in sorted(directory.glob("engagement_*.json")):
            try:
                summary, _mgr = _load_engagement_summary(path)
            except EngagementNotFoundError:
                continue  # skip unreadable/corrupt files, don't fail the whole listing
            summaries.append(summary)
    return ListEngagementsResponse(engagements=summaries)


def get_engagement(request: GetEngagementRequest) -> GetEngagementResponse:
    directory = _engagement_dir(request.output_base)
    engagement_id = request.engagement_id
    if engagement_id.endswith(".json"):
        engagement_id = engagement_id[: -len(".json")]
    path = directory / f"{engagement_id}.json"
    if not path.is_file():
        raise EngagementNotFoundError(f"No engagement found for id '{request.engagement_id}'")

    summary, mgr = _load_engagement_summary(path)
    timeline = [
        TimelineEntrySummary(
            timestamp=entry.get("timestamp", ""),
            module=entry.get("module", ""),
            action=entry.get("action", ""),
            detail=entry.get("detail", ""),
        )
        for entry in mgr.get_timeline()
    ]
    return GetEngagementResponse(summary=summary, timeline=timeline, loot_summary=dict(mgr.loot_summary))


# ── reconforge_get_scope ─────────────────────────────────────────────


def get_scope(request: GetScopeRequest) -> GetScopeResponse:
    try:
        auth = ScopeAuthorization.from_file(request.scope_file)
    except ValueError as exc:
        raise ScopeFileError(str(exc)) from exc

    is_expired = datetime.now(timezone.utc) > auth.valid_until
    return GetScopeResponse(
        allowed_targets=list(auth.allowed_targets),
        approval_id=auth.approval_id,
        valid_until=auth.valid_until.isoformat(),
        is_expired=is_expired,
    )


# ── reconforge_plan_workflow ─────────────────────────────────────────


def plan_workflow(request: PlanWorkflowRequest) -> PlanWorkflowResponse:
    try:
        target = parse_target(request.target)
    except TargetValidationError as exc:
        raise InvalidMCPRequestError(str(exc)) from exc

    explicit = request.modules is not None
    requested = list(request.modules) if request.modules else list(_DEFAULT_PIPELINE_ORDER)
    ordered = [m for m in _DEFAULT_PIPELINE_ORDER if m in requested]
    ordered += [m for m in requested if m not in _DEFAULT_PIPELINE_ORDER]

    steps: list[PlannedStep] = []
    required_approvals: list[str] = []
    for name in ordered:
        summary = _module_summary(name)
        conditional = (not explicit) and name in _CONDITIONAL_MODULES
        steps.append(
            PlannedStep(
                module=name,
                phases=summary.valid_phases,
                tool_wrappers=summary.tool_wrappers,
                conditional=conditional,
                opt_in_capabilities=summary.opt_in_capabilities,
            )
        )
        if summary.opt_in_capabilities:
            required_approvals.append(f"{name}: {'; '.join(summary.opt_in_capabilities)}")

    warnings: list[str] = []
    scope_decision = ScopeDecision(enforced=False)
    if request.scope_file:
        try:
            auth = ScopeAuthorization.from_file(request.scope_file)
        except ValueError as exc:
            scope_decision = ScopeDecision(enforced=True, target_allowed=None, reason=str(exc))
            warnings.append(f"Scope file could not be validated: {exc}")
        else:
            allowed = request.target in auth.allowed_targets or target.display in auth.allowed_targets
            scope_decision = ScopeDecision(
                enforced=True,
                target_allowed=allowed,
                reason="target present in allowed_targets" if allowed else "target not present in allowed_targets",
            )
            if not allowed:
                warnings.append(f"Target '{request.target}' is not in the scope file's allowed_targets.")
    else:
        warnings.append("No scope_file supplied — this plan has not been scope-validated.")

    if not explicit:
        warnings.append(
            "ad/web/api are conditionally queued at execution time based on what "
            "surface/network actually discover (open ports/services) — this plan "
            "cannot predict in advance whether they will run."
        )

    return PlanWorkflowResponse(
        normalized_target=target.display,
        selected_modules=steps,
        scope_decision=scope_decision,
        warnings=warnings,
        required_approvals=required_approvals,
        recommended_execution_order=ordered,
    )


# ── reconforge_dry_run ────────────────────────────────────────────────


def dry_run(request: DryRunRequest) -> DryRunResponse:
    try:
        parse_target(request.target)
    except TargetValidationError as exc:
        raise InvalidMCPRequestError(str(exc)) from exc

    module_cls = _module_class(request.module)
    valid_phases = list(module_cls.VALID_PHASES)
    if request.phases:
        unknown = [p for p in request.phases if p not in valid_phases]
        if unknown:
            raise UnknownPhaseError(
                f"Unknown phase(s) for module '{request.module}': {unknown}. "
                f"Valid phases: {valid_phases}"
            )

    scope = None
    if request.scope_file:
        try:
            scope = ScopeAuthorization.from_file(request.scope_file)
        except ValueError as exc:
            raise ScopeFileError(str(exc)) from exc

    kwargs: dict[str, Any] = {
        "target": request.target,
        "output_base": request.output_base,
        "opsec_mode": request.opsec_profile,
        "verbose": False,
        "dry_run": True,
        "timeout": request.timeout,
        "scope": scope,
        "approval_id": request.approval_id,
    }
    if request.module == "ad":
        kwargs["domain"] = request.domain

    module = module_cls(**kwargs)

    warnings: list[str] = []
    try:
        module.run(phases=request.phases)
    except ReconForgeError as exc:
        warnings.append(f"Module raised during dry-run: {exc}")

    return DryRunResponse(
        module=request.module,
        target=request.target,
        phases_run=list(request.phases) if request.phases else valid_phases,
        commands=module.runner.get_command_log(),
        artifacts_written=[str(module.output.module_dir(module_cls.MODULE_NAME))],
        warnings=warnings,
    )
