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
