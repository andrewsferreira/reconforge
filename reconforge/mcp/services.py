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
import json
import platform
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import modules
from core.authorization_gate import ScopeAuthorization
from core.config_loader import ConfigLoader
from core.engagement import EngagementManager
from core.exceptions import EngagementError, ReconForgeError, TargetValidationError, ValidationError
from core.exceptions import EngagementNotFoundError as CoreEngagementNotFoundError
from core.logger import sanitize_log
from core.output_manager import OutputManager
from core.runner import validate_arg
from core.target_parser import parse_target
from core.validators import validate_url
from core.version import __version__ as RECONFORGE_VERSION
from reconforge.mcp import approvals, jobs
from reconforge.mcp.errors import (
    EngagementNotFoundError,
    ExecutionConflictError,
    FindingNotFoundError,
    InvalidMCPRequestError,
    PolicyBlockedError,
    ScopeFileError,
    UnknownPhaseError,
)
from reconforge.mcp.policy import ExecutionTier, classify_phase, evaluate, requirements_for
from reconforge.mcp.sanitization import sanitize_untrusted_text
from reconforge.mcp.schemas import (
    MODULE_NAMES,
    DryRunRequest,
    DryRunResponse,
    EngagementSummary,
    ExecuteApprovedPhaseRequest,
    ExecuteApprovedPhaseResponse,
    GenerateReportRequest,
    GenerateReportResponse,
    GetApprovalStatusRequest,
    GetApprovalStatusResponse,
    GetEngagementRequest,
    GetEngagementResponse,
    GetExecutionStatusRequest,
    GetExecutionStatusResponse,
    GetFindingRequest,
    GetFindingResponse,
    GetFindingsRequest,
    GetFindingsResponse,
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
    RequestExecutionRequest,
    RequestExecutionResponse,
    SanitizedFinding,
    ScopeDecision,
    StartExecutionRequest,
    StartExecutionResponse,
    SummarizeFindingsRequest,
    SummarizeFindingsResponse,
    TimelineEntrySummary,
    TrustedFindingMetadata,
    UntrustedFindingEvidence,
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

# web/api accept a bare host or a full "http(s)://host[:port]" URL —
# WebModule/APIModule._normalise_url() prepends "http://" if no scheme is
# given, then validates with validate_url(), which permits a non-default
# port. Every other module only ever receives a bare IP/CIDR/hostname
# (parse_target()). Using parse_target() unconditionally for a single-
# module operation (dry_run/_authorize_execution) would reject a target
# the module itself would happily accept, e.g. "127.0.0.1:8080" — real
# bug found while building the lab.vulnerable_app.py integration test in
# MCP Phase 11, fixed by dispatching on module here instead.
_URL_TARGET_MODULES = frozenset({"web", "api"})


def _validate_target_for_module(target: str, module: str) -> str:
    """Validate *target* using the same rules the named module's own
    constructor would apply, so dry_run/request_execution never reject
    a target the module would actually accept (or vice versa). Returns
    the normalized form used for canonical hashing
    (reconforge/mcp/approvals.py::canonical_request_hash) — for web/api
    this is the scheme-qualified URL a bare host normalizes to; for
    every other module the target grammar has no equivalent
    normalization step, so the stripped input is returned unchanged.

    validate_url() alone only checks scheme/netloc/no-userinfo — unlike
    parse_target(), it does not reject shell metacharacters, so a
    web/api target is also run through validate_arg() (the same check
    core/runner.py applies to every constructed subprocess argument).
    list[str] subprocess execution (never shell=True) already makes such
    characters inert against real injection, but rejecting them here
    keeps web/api targets held to the same immediate, clear-error
    input-quality bar every other module's target already gets from
    parse_target(), instead of silently accepting nonsense that would
    otherwise only surface as a confusing failure deep inside a module.
    """
    if module in _URL_TARGET_MODULES:
        candidate = target if target.startswith(("http://", "https://")) else f"http://{target}"
        try:
            validate_url(candidate)
            validate_arg(candidate, "target")
        # InvalidToolArgumentError is itself a ValidationError subclass
        # (core/exceptions.py) — one clause, not two, so there is no
        # except-ordering trap where the broader type silently swallows
        # the narrower one before it's ever reached.
        except ValidationError as exc:
            raise InvalidMCPRequestError(str(exc)) from exc
        return candidate
    try:
        parse_target(target)
    except TargetValidationError as exc:
        raise InvalidMCPRequestError(str(exc)) from exc
    return target.strip()

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
        approval_configured=bool(auth.approval_id),
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
        phase_tiers = {phase: classify_phase(name, phase).value for phase in summary.valid_phases}
        steps.append(
            PlannedStep(
                module=name,
                phases=summary.valid_phases,
                phase_tiers=phase_tiers,
                tool_wrappers=summary.tool_wrappers,
                conditional=conditional,
                opt_in_capabilities=summary.opt_in_capabilities,
            )
        )
        elevated_phases = [
            phase
            for phase, tier in phase_tiers.items()
            if tier in (ExecutionTier.INTRUSIVE.value, ExecutionTier.CREDENTIAL_USE.value)
        ]
        if elevated_phases:
            required_approvals.append(f"{name}: {', '.join(elevated_phases)} ({', '.join(phase_tiers[p] for p in elevated_phases)})")

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
    _validate_target_for_module(request.target, request.module)

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


# ── reconforge_get_findings / reconforge_get_finding / summarize / report ──

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_CONFIDENCE_ORDER = ("confirmed", "high", "medium", "low", "heuristic")


def _iter_findings_files(output_base: str, target: str | None, module: str | None) -> list[Path]:
    base = Path(output_base)
    if not base.is_dir():
        return []

    if target:
        target_dirs = [base / OutputManager._sanitize(target)]
    else:
        # "workflow" holds engagement/vault files, not a per-target output
        # tree (see _engagement_dir above) — exclude it from an unscoped scan.
        target_dirs = [d for d in base.iterdir() if d.is_dir() and d.name != "workflow"]

    files: list[Path] = []
    for target_dir in target_dirs:
        if not target_dir.is_dir():
            continue
        module_dirs = [target_dir / module] if module else list(target_dir.iterdir())
        for module_dir in module_dirs:
            candidate = module_dir / "findings.json"
            if candidate.is_file():
                files.append(candidate)
    return sorted(files)


def _load_raw_findings(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [f for f in data if isinstance(f, dict)]


def _load_findings(output_base: str, target: str | None, module: str | None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in _iter_findings_files(output_base, target, module):
        findings.extend(_load_raw_findings(path))
    return findings


def _severity_rank(value: str) -> int:
    return _SEVERITY_ORDER.index(value) if value in _SEVERITY_ORDER else len(_SEVERITY_ORDER)


def _confidence_rank(value: str) -> int:
    return _CONFIDENCE_ORDER.index(value) if value in _CONFIDENCE_ORDER else len(_CONFIDENCE_ORDER)


def _sanitize_finding(raw: dict[str, Any]) -> SanitizedFinding:
    description, description_truncated = sanitize_untrusted_text(str(raw.get("description", "")))
    evidence, evidence_truncated = sanitize_untrusted_text(str(raw.get("evidence", "")))
    truncated = description_truncated or evidence_truncated

    references = raw.get("references", [])
    if not isinstance(references, list):
        references = []

    return SanitizedFinding(
        trusted_metadata=TrustedFindingMetadata(
            finding_id=str(raw.get("id", "")),
            finding_type=str(raw.get("finding_type", "")),
            severity=str(raw.get("severity", "info")),
            confidence=str(raw.get("confidence", "low")),
            confidence_reason=sanitize_log(str(raw.get("confidence_reason", ""))),
            target=str(raw.get("target", "")),
            module=str(raw.get("module", "")),
            phase=str(raw.get("phase", "")),
            timestamp=str(raw.get("timestamp", "")),
        ),
        untrusted_evidence=UntrustedFindingEvidence(
            description=description,
            evidence=evidence,
            truncated=truncated,
        ),
        recommendation=sanitize_log(str(raw.get("recommendation", ""))),
        references=[str(r) for r in references],
    )


def get_findings(request: GetFindingsRequest) -> GetFindingsResponse:
    raw = _load_findings(request.output_base, request.target, request.module)
    if request.severity:
        raw = [f for f in raw if f.get("severity") == request.severity]
    if request.confidence:
        raw = [f for f in raw if f.get("confidence") == request.confidence]

    total = len(raw)
    limited = raw[: request.limit]
    return GetFindingsResponse(
        findings=[_sanitize_finding(f) for f in limited],
        total_count=total,
        truncated=total > len(limited),
    )


def get_finding(request: GetFindingRequest) -> GetFindingResponse:
    raw = _load_findings(request.output_base, request.target, request.module)
    match = next((f for f in raw if str(f.get("id", "")) == request.finding_id), None)
    if match is None:
        raise FindingNotFoundError(f"No finding found for id '{request.finding_id}'")
    return GetFindingResponse(finding=_sanitize_finding(match))


def summarize_findings(request: SummarizeFindingsRequest) -> SummarizeFindingsResponse:
    raw = _load_findings(request.output_base, request.target, request.module)

    by_severity: dict[str, int] = {}
    by_confidence: dict[str, int] = {}
    by_module: dict[str, int] = {}
    for finding in raw:
        severity = str(finding.get("severity", "info"))
        confidence = str(finding.get("confidence", "low"))
        module_name = str(finding.get("module", ""))
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_confidence[confidence] = by_confidence.get(confidence, 0) + 1
        if module_name:
            by_module[module_name] = by_module.get(module_name, 0) + 1

    top = sorted(
        raw,
        key=lambda f: (_severity_rank(str(f.get("severity", "info"))), _confidence_rank(str(f.get("confidence", "low")))),
    )[:10]

    return SummarizeFindingsResponse(
        total=len(raw),
        by_severity=by_severity,
        by_confidence=by_confidence,
        by_module=by_module,
        modules_with_findings=sorted(by_module.keys()),
        top_findings=[_sanitize_finding(f).trusted_metadata for f in top],
    )


def _render_executive_report(target: str, findings: list[SanitizedFinding]) -> str:
    by_severity: dict[str, int] = {}
    for finding in findings:
        severity = finding.trusted_metadata.severity
        by_severity[severity] = by_severity.get(severity, 0) + 1

    lines = [f"# Executive Summary — {target}", "", f"**Total findings:** {len(findings)}", ""]
    for severity in _SEVERITY_ORDER:
        if severity in by_severity:
            lines.append(f"- {severity.capitalize()}: {by_severity[severity]}")
    lines.append("")
    lines.append("## Top Risks")
    if not findings:
        lines.append("(none)")
    for finding in findings[:5]:
        m = finding.trusted_metadata
        lines.append(f"- [{m.severity}/{m.confidence}] {m.finding_type} on {m.target} ({m.module})")
    return "\n".join(lines)


def _render_technical_report(target: str, findings: list[SanitizedFinding]) -> str:
    lines = [f"# Technical Findings Report — {target}", "", f"**Total findings:** {len(findings)}", ""]
    for finding in findings:
        m = finding.trusted_metadata
        e = finding.untrusted_evidence
        lines.append(f"## {m.finding_type} — {m.severity}/{m.confidence}")
        lines.append(f"- Target: {m.target}")
        lines.append(f"- Module/Phase: {m.module}/{m.phase}")
        if m.confidence_reason:
            lines.append(f"- Confidence reason: {m.confidence_reason}")
        lines.append("")
        if e.description:
            lines.append(f"Description: {e.description}")
        if e.evidence:
            lines.append(f"Evidence: {e.evidence}")
        if finding.recommendation:
            lines.append(f"Recommendation: {finding.recommendation}")
        lines.append("")
    if not findings:
        lines.append("(no findings)")
    return "\n".join(lines)


def generate_report(request: GenerateReportRequest) -> GenerateReportResponse:
    raw = _load_findings(request.output_base, request.target, None)
    findings = sorted(
        (_sanitize_finding(f) for f in raw),
        key=lambda sf: (_severity_rank(sf.trusted_metadata.severity), _confidence_rank(sf.trusted_metadata.confidence)),
    )

    if request.report_type == "executive":
        content = _render_executive_report(request.target, findings)
    else:
        content = _render_technical_report(request.target, findings)

    return GenerateReportResponse(
        report_type=request.report_type,
        target=request.target,
        content=content,
        generated_from_finding_count=len(findings),
    )


# ── reconforge_execute_approved_phase ─────────────────────────────────
#
# The one tool in this package that can trigger real (non-dry-run)
# execution. Every check below is independently re-verified here — none
# of it is trusted from the request alone, per
# docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md §6's 17-point verification list:
#  (1)/(2) engagement exists and is active — _load_engagement_summary()
#      + mgr.status check.
#  (3)/(4)/(11) target allowed, scope enforced, approval valid —
#      ScopeAuthorization.assert_authorized(), the exact mechanism the
#      CLI's --enforce-scope already uses.
#  (5)/(6) module/phase exist — pydantic Literal + VALID_PHASES check.
#  (7) phase enabled — no separate enable/disable registry exists yet;
#      "exists in VALID_PHASES" is the current definition of enabled.
#  (8) OPSEC profile allows the phase — enforced inside the real module
#      run (core/opsec_checks.py) exactly as it is for the CLI; not
#      duplicated here at the technique level, since no clean
#      phase-to-technique mapping exists to check against in advance.
#  (9) required tools available — best-effort, non-fatal (Runner already
#      handles a missing tool per-command; this would only add an
#      earlier, coarser warning).
#  (10) arguments pass existing validators — parse_target(); module
#      parameters are not accepted by this tool at all yet (see the
#      CREDENTIAL_USE rejection below), so there is nothing else to
#      validate.
#  (12) explicit_confirmation is true — checked by policy.evaluate(),
#      which never sets it itself.
#  (13) execution not already running — _EXECUTION_LOCK, a process-wide
#      non-blocking lock (this server is one process per Claude session
#      — a full multi-worker job queue is Phase 6, not needed yet).
#  (14) rate limits — not implemented (no config section exists yet:
#      docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md §9).
#  (15) output/timeout limits — Runner's own timeout/max_output_bytes,
#      passed through from the request.
#  (16)/(17) credentials only from an approved reference, never inline —
#      no credential-reference mechanism exists yet, so CREDENTIAL_USE-
#      tier phases are rejected outright rather than accepting inline
#      credentials through the MCP request.

_EXECUTION_LOCK = threading.Lock()


def _intrusive_execution_allowed() -> bool:
    """Reads config/mcp.yaml's ``mcp.allow_intrusive_execution`` — the
    server-wide off switch for INTRUSIVE-tier phases (see
    ``reconforge/mcp/policy.py::evaluate()``). Deliberately not derived
    from the MCP request in any way: an operator changes this by editing
    the file, not by anything a client can send."""
    return bool(ConfigLoader().load("mcp").get("mcp", {}).get("allow_intrusive_execution", False))


def _check_engagement_and_scope(
    *,
    engagement_id: str,
    output_base: str,
    target: str,
    scope_file: str | None,
    approval_id: str | None,
) -> tuple[bool, ScopeAuthorization | None]:
    """Shared by ``request_execution`` (creation time) and
    ``_consume_and_authorize`` (execution time, re-checked fresh since
    time has passed and the engagement/scope may no longer be valid).
    """
    has_engagement = False
    if engagement_id:
        engagement_path = _engagement_dir(output_base) / f"{engagement_id}.json"
        if engagement_path.is_file():
            try:
                _summary, mgr = _load_engagement_summary(engagement_path)
                has_engagement = mgr.status == "active"
            except EngagementNotFoundError:
                has_engagement = False

    scope = None
    if scope_file and approval_id:
        try:
            candidate_scope = ScopeAuthorization.from_file(scope_file)
            candidate_scope.assert_authorized(target=target, provided_approval_id=approval_id)
            scope = candidate_scope
        except ValueError:
            scope = None

    return has_engagement, scope


def request_execution(request: RequestExecutionRequest) -> RequestExecutionResponse:
    """The only MCP-reachable way to create an out-of-band approval
    request (``reconforge/mcp/approvals.py``). Never executes anything
    and never grants its own approval — the created request sits in
    ``awaiting_operator_approval`` until a human runs
    ``reconforge mcp approvals approve <request_id>`` in a process this
    MCP session has no path to. Every field needed to actually run the
    operation is captured into the resulting ``ApprovalRequest`` now,
    so ``reconforge_execute_approved_phase``/``reconforge_start_execution``
    need nothing but the returned ``request_id`` — there is nothing
    left for a client to supply, and therefore nothing left to tamper
    with, once this call returns.
    """
    normalized_target = _validate_target_for_module(request.target, request.module)

    module_cls = _module_class(request.module)
    valid_phases = list(module_cls.VALID_PHASES)
    if request.phase not in valid_phases:
        raise UnknownPhaseError(
            f"Unknown phase '{request.phase}' for module '{request.module}'. Valid phases: {valid_phases}"
        )

    tier = classify_phase(request.module, request.phase)
    if tier is ExecutionTier.CREDENTIAL_USE:
        raise PolicyBlockedError(
            f"'{request.module}/{request.phase}' is classified CREDENTIAL_USE. Credentialed "
            "execution through MCP is not implemented yet — no approved credential-reference "
            "mechanism exists, and this tool never accepts inline credentials. Run this phase "
            "via the CLI directly with your own -u/-p flags instead."
        )
    if tier is ExecutionTier.PROHIBITED:
        raise PolicyBlockedError(f"'{request.module}/{request.phase}' is a PROHIBITED-tier action.")

    # Requirements are graduated by tier (policy.py::requirements_for) —
    # SAFE_READ_ONLY needs neither an engagement nor a scope; every
    # tier that actually touches a target does. Checking these
    # unconditionally here, regardless of tier, would silently make
    # SAFE_READ_ONLY phases stricter than policy.py declares them to be.
    reqs = requirements_for(tier)
    has_engagement, scope = _check_engagement_and_scope(
        engagement_id=request.engagement_id,
        output_base=request.output_base,
        target=request.target,
        scope_file=request.scope_file,
        approval_id=request.approval_id,
    )
    if reqs.requires_engagement and not has_engagement:
        raise PolicyBlockedError(
            f"No active engagement found for engagement_id='{request.engagement_id}'. Create "
            "one first (see reconforge_list_engagements / 'reconforge workflow --engagement').",
            missing_requirements=("engagement_id",),
        )
    if reqs.requires_scope and scope is None:
        raise PolicyBlockedError(
            "Target is not authorized by a valid scope file — supply scope_file and a matching "
            "approval_id (see reconforge_get_scope).",
            missing_requirements=("validated scope (scope_file + target in allowed_targets)",),
        )
    if tier is ExecutionTier.INTRUSIVE and not _intrusive_execution_allowed():
        raise PolicyBlockedError(
            f"'{request.module}/{request.phase}' is INTRUSIVE-tier and mcp.allow_intrusive_execution "
            "is not enabled in config/mcp.yaml.",
            missing_requirements=(
                "mcp.allow_intrusive_execution=true in config/mcp.yaml (server-wide, operator-controlled)",
            ),
        )

    record = approvals.create_request(
        engagement_id=request.engagement_id,
        target=request.target,
        normalized_target=normalized_target,
        module=request.module,
        phase=request.phase,
        opsec_profile=request.opsec_profile,
        tier=tier.value,
        scope_reference=request.scope_file or "",
        output_base=request.output_base,
        domain=request.domain,
        scope_file=request.scope_file,
        approval_id=request.approval_id,
        timeout=request.timeout,
    )
    return RequestExecutionResponse(
        request_id=record.request_id,
        status=record.status,
        tier=tier.value,
        expires_at=record.expires_at,
    )


def get_approval_status(request: GetApprovalStatusRequest) -> GetApprovalStatusResponse:
    """Read-only poll of an approval request's current state. Never
    reveals anything a client couldn't already infer from having
    created the request — no scope/approval secrets, no hash."""
    record = approvals.get_request(request.request_id)
    return GetApprovalStatusResponse(
        request_id=record.request_id,
        status=record.status,
        engagement_id=record.engagement_id,
        target=record.target,
        module=record.module,
        phase=record.phase,
        tier=record.tier,
        created_at=record.created_at,
        expires_at=record.expires_at,
        approved_at=record.approved_at,
        denial_reason=record.denial_reason,
    )


def _consume_and_authorize(
    request_id: str,
) -> tuple[approvals.ApprovalRequest, type[Any], ExecutionTier, ScopeAuthorization | None]:
    """The only path by which MCP-triggered execution may proceed.

    Atomically consumes the referenced approval (raising if it isn't
    genuinely ``approved``, is expired, or was already consumed —
    see ``approvals.consume_if_approved``), then re-verifies engagement
    and scope *fresh* — time has passed since the request was approved,
    and either could have changed. If that fresh check fails, the
    approval has still been consumed: burning a stale approval and
    requiring a new one (and therefore a new human review) is the safer
    failure mode than either executing against outdated preconditions
    or leaving a spent approval reusable.
    """
    record = approvals.get_request(request_id)
    tier = ExecutionTier(record.tier)

    expected_hash = approvals.canonical_request_hash(
        engagement_id=record.engagement_id,
        normalized_target=record.normalized_target,
        module=record.module,
        phase=record.phase,
        opsec_profile=record.opsec_profile,
        tier=record.tier,
        scope_reference=record.scope_reference,
    )
    record = approvals.consume_if_approved(request_id, expected_hash=expected_hash)

    module_cls = _module_class(record.module)
    has_engagement, scope = _check_engagement_and_scope(
        engagement_id=record.engagement_id,
        output_base=record.output_base,
        target=record.target,
        scope_file=record.scope_file,
        approval_id=record.approval_id,
    )

    decision = evaluate(
        tier,
        has_engagement=has_engagement,
        has_validated_scope=scope is not None,
        has_operator_approval=True,
        intrusive_execution_allowed=_intrusive_execution_allowed(),
    )
    if not decision.allowed:
        raise PolicyBlockedError(
            f"Execution denied for '{record.module}/{record.phase}' (tier={tier.value}) despite a "
            f"consumed approval — state changed since approval: {decision.reason}",
            missing_requirements=decision.missing_requirements,
        )

    return record, module_cls, tier, scope


def _execute_module_phase_locked(
    record: approvals.ApprovalRequest,
    module_cls: type[Any],
    tier: ExecutionTier,
    scope: ScopeAuthorization | None,
) -> ExecuteApprovedPhaseResponse:
    """Actually run *module_cls*'s phase. Assumes the caller already holds
    ``_EXECUTION_LOCK`` — this function neither acquires nor releases
    it, so it works equally from the synchronous tool (which wraps the
    whole call in acquire/finally-release) or a job worker thread
    (which acquires before starting the thread and releases when the
    thread finishes — ``threading.Lock`` doesn't require the releasing
    thread to be the one that acquired it).
    """
    warnings: list[str] = []
    kwargs: dict[str, Any] = {
        "target": record.target,
        "output_base": record.output_base,
        "opsec_mode": record.opsec_profile,
        "verbose": False,
        "dry_run": False,
        "timeout": record.timeout,
        "scope": scope,
        "approval_id": record.approval_id,
    }
    if record.module == "ad":
        kwargs["domain"] = record.domain

    module = module_cls(**kwargs)
    try:
        module.run(phases=[record.phase])
    except ReconForgeError as exc:
        warnings.append(f"Module raised during execution: {exc}")

    return ExecuteApprovedPhaseResponse(
        module=record.module,
        phase=record.phase,
        target=record.target,
        tier=tier.value,
        findings_count=len(module.findings_mgr.get_all()),
        artifacts_written=[str(module.output.module_dir(module_cls.MODULE_NAME))],
        warnings=warnings,
    )


def execute_approved_phase(request: ExecuteApprovedPhaseRequest) -> ExecuteApprovedPhaseResponse:
    # Lock first, consume second: a busy server process must reject the
    # call without ever touching the approval record. Consuming first
    # would burn a genuinely valid, operator-approved request on a
    # transient concurrency conflict that has nothing to do with whether
    # the approval itself was good — forcing a fresh operator review for
    # no real reason. With the lock acquired first, a conflict here
    # leaves the approval untouched and still consumable on retry.
    if not _EXECUTION_LOCK.acquire(blocking=False):
        raise ExecutionConflictError("Another execution is already in progress on this server process.")
    try:
        record, module_cls, tier, scope = _consume_and_authorize(request.request_id)
        return _execute_module_phase_locked(record, module_cls, tier, scope)
    finally:
        _EXECUTION_LOCK.release()


# ── reconforge_start_execution / reconforge_get_execution_status ────


def start_execution(request: StartExecutionRequest) -> StartExecutionResponse:
    job = jobs.start_execution(request.request_id)
    return StartExecutionResponse(job_id=job.job_id, status=job.status)


def get_execution_status(request: GetExecutionStatusRequest) -> GetExecutionStatusResponse:
    job = jobs.get_execution_status(request.job_id)
    return GetExecutionStatusResponse(
        job_id=job.job_id,
        status=job.status,
        module=job.module,
        phase=job.phase,
        target=job.target,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        result=job.result,
        error=job.error,
        error_code=job.error_code,
    )
