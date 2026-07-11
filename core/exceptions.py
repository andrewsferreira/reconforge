"""ReconForge Exceptions - Custom exception hierarchy.

Author: Andrews Ferreira

Provides a structured exception hierarchy for the framework so that
callers can handle errors at the appropriate granularity.
"""

from typing import Optional


# ── Base ────────────────────────────────────────────────────────────

class ReconForgeError(Exception):
    """Root exception for all ReconForge errors."""

    def __init__(self, message: str = "", detail: Optional[str] = None):
        self.detail = detail
        full = f"{message} — {detail}" if detail else message
        super().__init__(full)


# ── Configuration ───────────────────────────────────────────────────

class ConfigError(ReconForgeError):
    """Raised when a configuration file is missing, invalid, or malformed."""


class ProfileNotFoundError(ConfigError):
    """Raised when a requested OPSEC profile does not exist."""


# ── Validation ──────────────────────────────────────────────────────

class ValidationError(ReconForgeError):
    """Raised when user-supplied input fails validation."""

    def __init__(self, field: str, value: str, reason: str = ""):
        self.field = field
        self.value = value
        self.reason = reason
        msg = f"Invalid {field}: {value!r}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)


class TargetValidationError(ValidationError):
    """Raised when a target specification is invalid."""

    def __init__(self, value: str, reason: str = ""):
        super().__init__(field="target", value=value, reason=reason)


class PortValidationError(ValidationError):
    """Raised when a port specification is invalid."""

    def __init__(self, value: str, reason: str = ""):
        super().__init__(field="port", value=value, reason=reason)


# ── Execution ───────────────────────────────────────────────────────

class ExecutionError(ReconForgeError):
    """Raised when a subprocess / tool execution fails."""

    def __init__(self, command: str, returncode: int = -1,
                 stderr: str = "", detail: Optional[str] = None):
        self.command = command
        self.returncode = returncode
        self.stderr = stderr
        msg = f"Command failed (rc={returncode}): {command}"
        super().__init__(msg, detail=detail)


class ToolNotFoundError(ExecutionError):
    """Raised when a required external tool is not on PATH."""

    def __init__(self, tool: str):
        self.tool = tool
        super().__init__(command=tool, returncode=-2,
                         detail=f"{tool} not found on PATH")


class TimeoutError(ExecutionError):
    """Raised when a command exceeds its timeout."""

    def __init__(self, command: str, timeout: int):
        self.timeout = timeout
        super().__init__(command=command, returncode=-1,
                         detail=f"Timed out after {timeout}s")


class KillSwitchBlockedError(ExecutionError):
    """Raised when execution is blocked by the global kill-switch."""

    def __init__(self, command: str):
        super().__init__(command=command, returncode=-5,
                         detail="Execution blocked: kill-switch is active")


class PolicyBlockedError(ExecutionError):
    """Raised when execution is blocked by the risk policy engine."""

    def __init__(self, command: str, reason: str = ""):
        self.reason = reason
        super().__init__(command=command, returncode=-6, detail=reason)


class InvalidCommandError(ExecutionError):
    """Raised when a command could not be parsed/split for execution."""

    def __init__(self, command: str, reason: str = ""):
        super().__init__(command=command, returncode=-4, detail=reason)


# ── Scope / Authorization ───────────────────────────────────────────

class ScopeViolationError(ReconForgeError):
    """Raised when a target/command falls outside the authorized engagement scope."""


# ── Module / Workflow ───────────────────────────────────────────────

class ModuleError(ReconForgeError):
    """Raised when a module encounters an unrecoverable error."""

    def __init__(self, module: str, message: str = "",
                 detail: Optional[str] = None):
        self.module = module
        super().__init__(f"[{module}] {message}", detail=detail)


class PhaseError(ModuleError):
    """Raised when a specific phase inside a module fails."""

    def __init__(self, module: str, phase: str, message: str = "",
                 detail: Optional[str] = None):
        self.phase = phase
        super().__init__(module=module, message=f"Phase '{phase}': {message}",
                         detail=detail)


class WorkflowError(ReconForgeError):
    """Raised when the workflow orchestrator encounters an error."""


class WorkflowAbortedError(WorkflowError):
    """Raised when a workflow is deliberately aborted (e.g. critical failure)."""


# ── Credential Vault ────────────────────────────────────────────────

class CredentialVaultError(ReconForgeError):
    """Raised on credential vault operation failures."""


# ── Engagement ──────────────────────────────────────────────────────

class EngagementError(ReconForgeError):
    """Raised on engagement lifecycle errors."""


class EngagementNotFoundError(EngagementError):
    """Raised when a saved engagement cannot be found."""
