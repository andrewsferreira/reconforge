"""ReconForge AD - NetExec (formerly CrackMapExec) Tool Wrapper.

Wraps netexec for multi-protocol AD enumeration.

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts are
read from ``tools.yaml``.

Author: Andrews Ferreira
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from core.runner import RC_TOOL_NOT_FOUND, Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class NetexecTool:
    """Wrapper for netexec (nxc / crackmapexec) multi-protocol enumeration."""

    TOOL_NAMES = ("netexec", "nxc", "crackmapexec")

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 config: ConfigLoader | None = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self.tool_cfg = ToolConfig(config, "netexec")
        self._resolved: str | None = None

    def _resolve_binary(self) -> str | None:
        """Resolve the actual binary name."""
        if self._resolved is not None:
            return self._resolved
        for name in self.TOOL_NAMES:
            if self.runner.check_tool(name):
                self._resolved = name
                return name
        self._resolved = ""
        return None

    def is_available(self) -> bool:
        """Check if netexec (or any alias) is installed."""
        binary = self._resolve_binary()
        return bool(binary)

    # ------------------------------------------------------------------
    # SMB enumeration
    # ------------------------------------------------------------------

    def smb_enum(self, target: str, username: str = "",
                 password: str = "", domain: str = "",
                 options: list[str] | None = None,
                 timeout: int = 180) -> RunResult:
        """Run SMB enumeration with netexec.

        Args:
            target: Target IP or CIDR range.
            username: Username for authentication.
            password: Password for authentication.
            domain: Domain name.
            options: Additional netexec options as a list
                     (e.g. ["--shares"] or ["--users"]).
            timeout: Command timeout.
        """
        binary = self._resolve_binary()
        if not binary:
            return self._tool_missing()

        self.logger.info(f"Running netexec SMB enum on {target}")
        out = self.output_dir / "netexec_smb.txt"

        cmd: list[str] = [binary, "smb", target]
        if username and password:
            cmd += ["-u", username, "-p", password]
            if domain:
                cmd += ["-d", domain]
        else:
            cmd += ["-u", "", "-p", ""]

        if options:
            cmd.extend(options)

        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    # ------------------------------------------------------------------
    # LDAP enumeration
    # ------------------------------------------------------------------

    def ldap_enum(self, target: str, username: str = "",
                  password: str = "", domain: str = "",
                  module: str = "",
                  options: list[str] | None = None,
                  timeout: int = 180) -> RunResult:
        """Run LDAP enumeration with netexec.

        Args:
            target: Target DC IP or hostname.
            username: Username for authentication.
            password: Password for authentication.
            domain: Domain name.
            module: Netexec LDAP module to use.
            options: Additional options as a list.
            timeout: Command timeout.
        """
        binary = self._resolve_binary()
        if not binary:
            return self._tool_missing()

        self.logger.info(f"Running netexec LDAP enum on {target}")
        out = self.output_dir / "netexec_ldap.txt"

        cmd: list[str] = [binary, "ldap", target]
        if username and password:
            cmd += ["-u", username, "-p", password]
            if domain:
                cmd += ["-d", domain]
        else:
            cmd += ["-u", "", "-p", ""]

        if module:
            cmd += ["-M", module]
        if options:
            cmd.extend(options)

        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    # ------------------------------------------------------------------
    # SMB signing check
    # ------------------------------------------------------------------

    def check_signing(self, target: str, timeout: int = 60) -> RunResult:
        """Check SMB signing status on target(s)."""
        binary = self._resolve_binary()
        if not binary:
            return self._tool_missing()

        self.logger.info(f"Checking SMB signing on {target}")
        out = self.output_dir / "netexec_signing.txt"
        relay_list = str(self.output_dir / "relay_targets.txt")

        cmd: list[str] = [
            binary, "smb", target,
            "--gen-relay-list", relay_list,
        ]
        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    # ------------------------------------------------------------------
    # Bloodhound ingest via netexec
    # ------------------------------------------------------------------

    def bloodhound_ingest(self, target: str, username: str,
                          password: str, domain: str = "",
                          timeout: int = 300) -> RunResult:
        """Collect bloodhound data using netexec."""
        binary = self._resolve_binary()
        if not binary:
            return self._tool_missing()

        self.logger.info(f"Running netexec bloodhound ingest on {target}")
        out = self.output_dir / "netexec_bloodhound.txt"

        cmd: list[str] = [
            binary, "ldap", target,
            "-u", username, "-p", password,
        ]
        if domain:
            cmd += ["-d", domain]
        cmd += ["--bloodhound", "--collection", "All"]

        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _tool_missing(self) -> RunResult:
        """Return a synthetic RunResult for a missing tool."""
        self.logger.warning("netexec / nxc / crackmapexec not found")
        return RunResult(
            command="netexec",
            returncode=RC_TOOL_NOT_FOUND,
            stdout="",
            stderr="Tool not found: netexec / nxc / crackmapexec",
            duration=0.0,
            success=False,
        )
