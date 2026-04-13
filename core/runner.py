"""ReconForge Runner - Secure subprocess execution with logging.

All commands should be passed as structured argument lists (list[str]).
String-based commands are still accepted for backwards compatibility but
will emit a deprecation warning.

Author: Andrews Ferreira
"""

import re
import subprocess
import shlex
import shutil
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Union

from core.exceptions import (
    ExecutionError,
    ToolNotFoundError,
    TimeoutError as ReconTimeoutError,
)


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

    def __init__(self, logger, timeout: int = 300, dry_run: bool = False):
        self.logger = logger
        self.timeout = timeout
        self.dry_run = dry_run
        self._command_log: List[str] = []

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
        """
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
            cmd_display = command

        effective_timeout = timeout or self.timeout
        self.logger.command(cmd_display)
        self._command_log.append(f"[{time.strftime('%H:%M:%S')}] {cmd_display}")

        if self.dry_run:
            self.logger.info(f"DRY RUN: {cmd_display}")
            return RunResult(
                command=cmd_display, returncode=0, stdout="", stderr="",
                duration=0.0, success=True
            )

        # Build argument list safely — never uses shell=True
        if isinstance(command, (list, tuple)):
            cmd_list = [str(a) for a in command]
        else:
            cmd_list = shlex.split(command)

        start = time.time()
        try:
            proc = subprocess.run(
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

            return result

        except subprocess.TimeoutExpired:
            duration = time.time() - start
            self.logger.error(f"Command timed out after {effective_timeout}s: {cmd_display}")
            return RunResult(
                command=cmd_display, returncode=-1, stdout="",
                stderr=f"Timeout after {effective_timeout}s",
                duration=duration, success=False
            )
        except FileNotFoundError:
            tool_name = cmd_list[0] if cmd_list else "unknown"
            self.logger.error(f"Tool not found: {tool_name}")
            return RunResult(
                command=cmd_display, returncode=-2, stdout="",
                stderr=f"Tool not found: {tool_name}",
                duration=0.0, success=False
            )
        except ValueError as e:
            # shlex.split can raise on malformed input
            self.logger.error(f"Invalid command: {e}")
            return RunResult(
                command=cmd_display, returncode=-4, stdout="",
                stderr=str(e), duration=0.0, success=False
            )
        except Exception as e:
            duration = time.time() - start
            self.logger.error(f"Command failed: {e}")
            return RunResult(
                command=cmd_display, returncode=-3, stdout="",
                stderr=str(e), duration=duration, success=False
            )

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
