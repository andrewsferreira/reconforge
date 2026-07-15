"""Typed errors for the MCP service layer.

A small, honest subset of the full error hierarchy the implementation
plan describes for a later phase (docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md
§8) — only the error types this phase's read-only tools actually raise.
Messages are safe to return to an MCP client: no stack traces, no
filesystem paths beyond what the caller itself supplied, no secrets.
"""

from __future__ import annotations


class MCPServiceError(Exception):
    """Base class for errors raised by reconforge/mcp/services.py."""

    code = "MCP_SERVICE_ERROR"


class InvalidMCPRequestError(MCPServiceError):
    """A tool argument failed validation before any lookup was attempted."""

    code = "INVALID_REQUEST"


class UnknownModuleError(MCPServiceError):
    """The requested module name is not one of ReconForge's five modules."""

    code = "UNKNOWN_MODULE"


class UnknownPhaseError(MCPServiceError):
    """The requested phase is not in the module's VALID_PHASES."""

    code = "UNKNOWN_PHASE"


class EngagementNotFoundError(MCPServiceError):
    """No engagement file matches the requested engagement id."""

    code = "ENGAGEMENT_NOT_FOUND"


class ScopeFileError(MCPServiceError):
    """The requested scope file is missing or fails to parse."""

    code = "SCOPE_FILE_ERROR"


class FindingNotFoundError(MCPServiceError):
    """No finding matches the requested finding id."""

    code = "FINDING_NOT_FOUND"


class PolicyBlockedError(MCPServiceError):
    """The requested execution does not satisfy its policy tier's
    requirements (reconforge/mcp/policy.py), or targets a tier that has
    no supported execution path yet (CREDENTIAL_USE, PROHIBITED).

    ``missing_requirements`` carries ``policy.py::PolicyDecision.missing_requirements``
    verbatim when the denial came from a failed tier-requirement check (e.g.
    ``("engagement_id", "approval_id")``) — empty for denials that aren't a
    missing-requirement list (CREDENTIAL_USE rejection, PROHIBITED tier).
    Surfaced in the MCP response's ``structuredContent`` by
    ``reconforge/mcp/tools.py`` so a client can act on it programmatically
    instead of parsing the message string.
    """

    code = "POLICY_BLOCKED"

    def __init__(self, message: str, *, missing_requirements: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.missing_requirements = missing_requirements


class ExecutionConflictError(MCPServiceError):
    """Another execution is already in progress on this server process."""

    code = "EXECUTION_CONFLICT"


class JobNotFoundError(MCPServiceError):
    """No execution job matches the requested job id (reconforge/mcp/jobs.py).

    Job state lives only in this server process's memory (no
    persistence across restarts) — this error also covers "the server
    was restarted since this job_id was issued.\""""

    code = "JOB_NOT_FOUND"


class ApprovalNotFoundError(MCPServiceError):
    """No approval request matches the requested request_id
    (reconforge/mcp/approvals.py). Approval requests are disk-persisted
    under ``mcp.approvals_dir``, so unlike ``JobNotFoundError`` this is
    not explained by a server restart — the id is simply wrong, or the
    request expired and was pruned."""

    code = "APPROVAL_NOT_FOUND"


class ApprovalNotApprovedError(MCPServiceError):
    """The referenced approval request exists but is not in the
    ``approved`` state (still ``awaiting_operator_approval``, or
    terminally ``denied``/``expired``/``consumed``/``revoked``) —
    execution cannot proceed. ``status`` carries the request's actual
    state so a client can distinguish "not yet" from "never will."""

    code = "APPROVAL_NOT_APPROVED"

    def __init__(self, message: str, *, status: str) -> None:
        super().__init__(message)
        self.status = status


class ApprovalExpiredError(MCPServiceError):
    """The approval request's TTL (``mcp.approval_ttl_minutes``) elapsed
    before it was consumed — including the case where it was approved
    but execution didn't happen before expiry. A new request must be
    created; an expired approval can never be revived."""

    code = "APPROVAL_EXPIRED"


class ApprovalRequestMismatchError(MCPServiceError):
    """The approval request's stored canonical hash does not match the
    hash recomputed from its own stored fields at consumption time —
    on-disk tampering or corruption between approval and execution.
    Execution is refused; this should never happen under normal
    operation, since the fields an approval binds are never mutated
    after creation."""

    code = "APPROVAL_REQUEST_MISMATCH"


class ApprovalStateError(MCPServiceError):
    """A requested state transition on an approval request is invalid
    for its current state — e.g. approving an already-denied request,
    revoking a request that was never approved, or two callers racing
    to consume the same approved request (exactly one wins; the other
    gets this error, not a second execution)."""

    code = "APPROVAL_STATE_ERROR"
