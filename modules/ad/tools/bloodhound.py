"""ReconForge AD - Bloodhound-Python Tool Wrapper.

Wraps bloodhound-python for Active Directory graph data collection.

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts and
collection method arguments are read from ``tools.yaml``.

Author: Andrews Ferreira
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from core.runner import RC_TOOL_NOT_FOUND, Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader


class BloodhoundTool:
    """Wrapper for bloodhound-python AD graph data collector."""

    TOOL_NAMES = ("bloodhound-python", "bloodhound.py")
    TOOL_CONFIG_KEY = "bloodhound_python"

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 config: ConfigLoader | None = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self.tool_cfg = ToolConfig(config, self.TOOL_CONFIG_KEY)
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
        """Check if bloodhound-python is installed."""
        binary = self._resolve_binary()
        return bool(binary)

    # ------------------------------------------------------------------
    # Collection methods
    # ------------------------------------------------------------------

    def collect_all(self, domain: str, username: str, password: str,
                    dc_ip: str = "", nameserver: str = "",
                    timeout: int = 600) -> RunResult:
        """Run full bloodhound collection (all methods)."""
        return self._run_collection(
            domain=domain, username=username, password=password,
            dc_ip=dc_ip, nameserver=nameserver,
            collection_method="All",
            output_prefix="bloodhound_all",
            timeout=timeout,
        )

    def collect_users(self, domain: str, username: str, password: str,
                      dc_ip: str = "", nameserver: str = "",
                      timeout: int = 300) -> RunResult:
        """Collect user objects only."""
        return self._run_collection(
            domain=domain, username=username, password=password,
            dc_ip=dc_ip, nameserver=nameserver,
            collection_method="Group",
            output_prefix="bloodhound_users",
            timeout=timeout,
        )

    def collect_groups(self, domain: str, username: str, password: str,
                       dc_ip: str = "", nameserver: str = "",
                       timeout: int = 300) -> RunResult:
        """Collect group membership data."""
        return self._run_collection(
            domain=domain, username=username, password=password,
            dc_ip=dc_ip, nameserver=nameserver,
            collection_method="Group",
            output_prefix="bloodhound_groups",
            timeout=timeout,
        )

    def collect_computers(self, domain: str, username: str, password: str,
                          dc_ip: str = "", nameserver: str = "",
                          timeout: int = 300) -> RunResult:
        """Collect computer objects."""
        return self._run_collection(
            domain=domain, username=username, password=password,
            dc_ip=dc_ip, nameserver=nameserver,
            collection_method="LocalAdmin,Session",
            output_prefix="bloodhound_computers",
            timeout=timeout,
        )

    def collect_sessions(self, domain: str, username: str, password: str,
                         dc_ip: str = "", nameserver: str = "",
                         timeout: int = 300) -> RunResult:
        """Collect session data (who is logged in where)."""
        return self._run_collection(
            domain=domain, username=username, password=password,
            dc_ip=dc_ip, nameserver=nameserver,
            collection_method="Session",
            output_prefix="bloodhound_sessions",
            timeout=timeout,
        )

    def collect_trusts(self, domain: str, username: str, password: str,
                       dc_ip: str = "", nameserver: str = "",
                       timeout: int = 300) -> RunResult:
        """Collect domain trust relationships."""
        return self._run_collection(
            domain=domain, username=username, password=password,
            dc_ip=dc_ip, nameserver=nameserver,
            collection_method="Trusts",
            output_prefix="bloodhound_trusts",
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_collection(self, domain: str, username: str, password: str,
                        dc_ip: str, nameserver: str,
                        collection_method: str, output_prefix: str,
                        timeout: int) -> RunResult:
        """Execute bloodhound-python with the given collection method."""
        binary = self._resolve_binary()
        if not binary:
            return self._tool_missing()

        self.logger.info(
            f"Running bloodhound-python collection ({collection_method}) "
            f"on {domain}"
        )

        bh_output_dir = self.output_dir / "bloodhound"
        bh_output_dir.mkdir(parents=True, exist_ok=True)

        cmd: list[str] = [
            binary,
            "-d", domain,
            "-u", username,
            "-p", password,
            "-c", collection_method,
            "--zip",
            "-o", str(bh_output_dir),
        ]

        if dc_ip:
            cmd += ["--dc-ip", dc_ip]
        if nameserver:
            cmd += ["-ns", nameserver]

        # OPSEC: stealth mode adjustments
        if self.opsec_mode == "stealth":
            cmd.append("--stealth")
            self.logger.info("OPSEC: Using stealth collection mode")

        effective_timeout = self.tool_cfg.effective_timeout(None, timeout)
        out = self.output_dir / f"{output_prefix}.txt"
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def _tool_missing(self) -> RunResult:
        """Return a synthetic RunResult for a missing tool."""
        self.logger.warning("bloodhound-python not found")
        return RunResult(
            command="bloodhound-python",
            returncode=RC_TOOL_NOT_FOUND,
            stdout="",
            stderr="Tool not found: bloodhound-python",
            duration=0.0,
            success=False,
        )
