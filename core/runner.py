"""ReconForge Runner - Secure subprocess execution with logging.

All commands should be passed as structured argument lists (list[str]).
String-based commands are still accepted for backwards compatibility but
will emit a deprecation warning.

Author: Andrews Ferreira
"""

import re
import subprocess  # nosec B404 - this is the framework's sole, audited execution layer (list[str] args, shell=False always; see Runner.run)
import shlex
import shutil
import os
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, TYPE_CHECKING, Union

from core.exceptions import (
    ExecutionError,
    ToolNotFoundError,
    TimeoutError as ReconTimeoutError,
    ScopeViolationError,
)
from core.risk_policy import RiskPolicyEngine
from core.logger import sanitize_log

if TYPE_CHECKING:
    from core.authorization_gate import ScopeAuthorization


# Characters / patterns that should never appear in a single argument
_SHELL_META = re.compile(r'[;&|`$(){}]')


def quote_args(*args: str) -> str:
    """Shell-quote each argument and join with spaces.

    .. deprecated:: 2.0
        Prefer passing commands as ``list[str]`` directly to
        :meth:`Runner.run` instead of building shell strings.
    """
    warnings.warn(
        "quote_args() is deprecated. Build commands as list[str] instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return " ".join(shlex.quote(a) for a in args)


def validate_arg(value: str, label: str = "argument") -> str:
    """Raise :class:`ValueError` if *value* contains shell meta-characters.

    This is an extra safety net on top of :func:`shlex.split`, which
    already avoids shell interpretation.  We reject values that look
    like injection attempts *before* they reach the subprocess layer.
    """
    if _SHELL_META.search(value):
        raise ValueError(
            f"Potentially unsafe characters in {label}: {value!r}"
        )
    return value


@dataclass
class RunResult:
    """Result of a command execution."""
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration: float
    success: bool
    output_file: Optional[str] = None


class Runner:
    """Secure subprocess runner with timeout and logging support.

    Commands are always executed via :func:`subprocess.run` with an
    argument **list** (no shell=True) produced by :func:`shlex.split`.
    """

    def __init__(self, logger, timeout: int = 300, dry_run: bool = False,
                 target: Optional[str] = None,
                 scope: Optional["ScopeAuthorization"] = None,
                 approval_id: Optional[str] = None):
        """
        Args:
            target: The primary target this runner executes commands against.
                Required for scope enforcement to take effect.
            scope: Optional authorized-scope document (from --scope-file /
                --enforce-scope). When set, *target* must be within scope —
                checked both here at construction time (fail closed before
                any command runs) and again at the top of every run() call,
                so a scope that expires mid-execution also blocks further
                commands.
            approval_id: Approval id to check against *scope*.
        """
        self.logger = logger
        self.timeout = timeout
        self.dry_run = dry_run
        self.target = target
        self.scope = scope
        self.approval_id = approval_id
        self._command_log: List[str] = []
        self._metrics: Dict[str, Any] = {
            "total_commands": 0,
            "failed_commands": 0,
            "total_duration_seconds": 0.0,
            "tools": {},  # tool -> stats
        }
        self._assert_target_in_scope()

    def _assert_target_in_scope(self) -> None:
        """Raise ScopeViolationError if self.target is outside self.scope.

        No-op when no scope is configured (--enforce-scope was not used) or
        no target is bound to this runner.
        """
        if self.scope is None or self.target is None:
            return
        try:
            self.scope.assert_authorized(
                target=self.target, provided_approval_id=self.approval_id or ""
            )
        except ValueError as e:
            raise ScopeViolationError(str(e)) from e

    def check_tool(self, tool_name: str) -> bool:
        """Check if an external tool is available on PATH."""
        return shutil.which(tool_name) is not None

    def run(self, command: Union[str, Sequence[str]], timeout: Optional[int] = None,
            output_file: Optional[Path] = None, env: Optional[dict] = None,
            stdin_data: Optional[str] = None) -> RunResult:
        """Execute a command and return structured result.

        Args:
            command: Command string **or** pre-split argument list.
            timeout: Override the default timeout for this invocation.
            output_file: If given, write stdout to this path.
            env: Optional environment dict for the child process.
            stdin_data: Optional string piped to the process stdin.

        Returns:
            :class:`RunResult` with captured stdout/stderr.

        Raises:
            ScopeViolationError: If this runner is scope-bound and the bound
                target is no longer authorized (e.g. the approval expired
                during a long-running scan).
        """
        self._assert_target_in_scope()

        # Normalise to a display string for logging
        if isinstance(command, (list, tuple)):
            cmd_display = " ".join(shlex.quote(str(a)) for a in command)
        else:
            # String commands are supported but deprecated
            warnings.warn(
                "Passing commands as strings to Runner.run() is deprecated. "
                "Use list[str] instead for safer execution.",
                DeprecationWarning,
                stacklevel=2,
            )
            cmd_display = str(command)

        # Redact secrets (passwords, tokens, hashes, ...) once, up front, so
        # every downstream consumer of cmd_display — the logger, the
        # in-memory command log, RunResult.command, and anything a caller
        # persists from it — sees the redacted form. Redacting only at some
        # call sites (as before) is exactly how secrets leaked into
        # save_command_log()/session notes while the logger's own output
        # stayed clean.
        cmd_display = sanitize_log(cmd_display)

        effective_timeout = timeout or self.timeout
        self.logger.command(cmd_display)
        self._command_log.append(f"[{time.strftime('%H:%M:%S')}] {cmd_display}")

        if self.dry_run:
            self.logger.info(f"DRY RUN: {cmd_display}")
            return RunResult(
                command=cmd_display, returncode=0, stdout="", stderr="",
                duration=0.0, success=True
            )
        if self._kill_switch_active():
            self.logger.error("Execution blocked by kill-switch control")
            return RunResult(
                command=cmd_display,
                returncode=-5,
                stdout="",
                stderr="Execution blocked: kill-switch is active",
                duration=0.0,
                success=False,
            )

        # Build argument list safely — never uses shell=True
        if isinstance(command, (list, tuple)):
            cmd_list = [str(a) for a in command]
        else:
            cmd_list = shlex.split(str(command))
        tool_name = cmd_list[0] if cmd_list else "unknown"
        policy_decision = RiskPolicyEngine.check(cmd_list)
        if not policy_decision.allowed:
            self.logger.error(policy_decision.reason)
            self._record_metrics(tool_name, 0.0, success=False)
            return RunResult(
                command=cmd_display,
                returncode=-6,
                stdout="",
                stderr=policy_decision.reason,
                duration=0.0,
                success=False,
            )

        start = time.time()
        try:
            proc = subprocess.run(  # nosec B603 - cmd_list is always list[str], shell=False (never shell=True); target/args validated upstream (core/target_parser.py, validate_arg)
                cmd_list,
                capture_output=True, text=True,
                timeout=effective_timeout, env=env,
                input=stdin_data,
            )
            duration = time.time() - start

            if output_file:
                output_file = Path(output_file)
                output_file.parent.mkdir(parents=True, exist_ok=True)
                output_file.write_text(proc.stdout)

            result = RunResult(
                command=cmd_display,
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration=duration,
                success=proc.returncode == 0,
                output_file=str(output_file) if output_file else None,
            )

            if not result.success:
                self.logger.debug(f"Command exited with code {proc.returncode}: {proc.stderr[:200]}")

            self._record_metrics(tool_name, duration, result.success)
            return result

        except subprocess.TimeoutExpired:
            duration = time.time() - start
            self.logger.error(f"Command timed out after {effective_timeout}s: {cmd_display}")
            self._record_metrics(tool_name, duration, success=False)
            return RunResult(
                command=cmd_display, returncode=-1, stdout="",
                stderr=f"Timeout after {effective_timeout}s",
                duration=duration, success=False
            )
        except FileNotFoundError:
            tool_name = cmd_list[0] if cmd_list else "unknown"
            self.logger.error(f"Tool not found: {tool_name}")
            self._record_metrics(tool_name, 0.0, success=False)
            return RunResult(
                command=cmd_display, returncode=-2, stdout="",
                stderr=f"Tool not found: {tool_name}",
                duration=0.0, success=False
            )
        except ValueError as e:
            # shlex.split can raise on malformed input
            self.logger.error(f"Invalid command: {e}")
            self._record_metrics(tool_name, 0.0, success=False)
            return RunResult(
                command=cmd_display, returncode=-4, stdout="",
                stderr=str(e), duration=0.0, success=False
            )
        except Exception as e:
            duration = time.time() - start
            self.logger.error(f"Command failed: {e}")
            self._record_metrics(tool_name, duration, success=False)
            return RunResult(
                command=cmd_display, returncode=-3, stdout="",
                stderr=str(e), duration=duration, success=False
            )

    @staticmethod
    def _kill_switch_active() -> bool:
        """Return True when global kill switch is enabled via env/file."""
        if os.getenv("RECONFORGE_KILL_SWITCH", "").strip() == "1":
            return True

        file_path = os.getenv("RECONFORGE_KILL_SWITCH_FILE", "").strip()
        if not file_path:
            return False
        p = Path(file_path)
        if not p.exists():
            return False
        content = p.read_text(encoding="utf-8").strip().lower()
        return content in {"1", "true", "on", "stop", "blocked"}

    def run_or_raise(self, command: Union[str, Sequence[str]],
                     timeout: Optional[int] = None,
                     output_file: Optional[Path] = None,
                     env: Optional[dict] = None,
                     stdin_data: Optional[str] = None) -> RunResult:
        """Execute a command and raise on failure.

        Same interface as :meth:`run`, but raises structured exceptions
        instead of returning a failed :class:`RunResult`.

        Raises:
            ToolNotFoundError: If the binary is not found.
            ReconTimeoutError: If the command times out.
            ExecutionError: If the command exits with a non-zero code.
        """
        result = self.run(command, timeout=timeout, output_file=output_file,
                          env=env, stdin_data=stdin_data)
        if result.success:
            return result

        if result.returncode == -2:
            tool = result.command.split()[0] if result.command else "unknown"
            raise ToolNotFoundError(tool)
        if result.returncode == -1 and "Timeout" in result.stderr:
            raise ReconTimeoutError(result.command, timeout or self.timeout)

        raise ExecutionError(
            command=result.command,
            returncode=result.returncode,
            stderr=result.stderr,
        )

    def check_tool_or_raise(self, tool_name: str) -> bool:
        """Check if a tool is available, raise if not.

        Raises:
            ToolNotFoundError: If the tool is not on PATH.
        """
        if not self.check_tool(tool_name):
            raise ToolNotFoundError(tool_name)
        return True

    def get_command_log(self) -> List[str]:
        """Return all commands executed in this session."""
        return list(self._command_log)

    def save_command_log(self, path: Path):
        """Save command log to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(self._command_log) + "\n")

    def _record_metrics(self, tool_name: str, duration: float, success: bool) -> None:
        self._metrics["total_commands"] += 1
        self._metrics["total_duration_seconds"] += max(duration, 0.0)
        if not success:
            self._metrics["failed_commands"] += 1
        tool = self._metrics["tools"].setdefault(
            tool_name,
            {"commands": 0, "failed": 0, "duration_seconds": 0.0},
        )
        tool["commands"] += 1
        tool["duration_seconds"] += max(duration, 0.0)
        if not success:
            tool["failed"] += 1

    def get_metrics(self) -> dict:
        """Return execution metrics for audit/observability."""
        total = self._metrics["total_commands"]
        failed = self._metrics["failed_commands"]
        return {
            **self._metrics,
            "error_rate": (failed / total) if total else 0.0,
        }
