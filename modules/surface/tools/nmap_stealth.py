"""ReconForge - Nmap Stealth Scan Tool Wrapper

Author: Andrews Ferreira

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Profile-aware: when a :class:`ProfileLoader` is provided, timing and
port range are read from the resolved OPSEC profile.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts and
scan profile arguments are read from ``tools.yaml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from core.runner import Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader
    from core.profile_loader import ProfileLoader


class NmapStealthTool:
    """Wrapper for nmap with OPSEC-aware stealth scanning."""

    TOOL_NAME = "nmap"
    TOOL_CONFIG_KEY = "nmap_surface"

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 profile: Optional["ProfileLoader"] = None,
                 config: Optional["ConfigLoader"] = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self.profile = profile
        self.tool_cfg = ToolConfig(config, self.TOOL_CONFIG_KEY)

    def is_available(self) -> bool:
        """Check if nmap is installed."""
        return self.runner.check_tool(self.TOOL_NAME)

    def _timing_flag(self) -> str:
        """Get nmap timing flag from profile or OPSEC mode fallback."""
        if self.profile:
            return f"-{self.profile.nmap_timing}"
        return {
            "stealth": "-T1",
            "normal": "-T3",
            "aggressive": "-T4",
        }.get(self.opsec_mode, "-T3")

    def _extra_timing_args(self) -> List[str]:
        """Return additional timing arguments from the profile."""
        args: List[str] = []
        if self.profile:
            delay = self.profile.scan_delay
            if delay and delay != "0":
                args += ["--scan-delay", delay]
            retries = self.profile.max_retries
            if retries is not None:
                args += ["--max-retries", str(retries)]
        return args

    def _default_port_range(self) -> str:
        """Return the port range from the profile or default."""
        if self.profile:
            pr = self.profile.get("surface.options.port_range")
            if pr:
                return str(pr)
        return "--top-ports 1000"

    def _base_cmd(self, extra_args: List[str], target: str,
                  output_prefix: str) -> List[str]:
        """Build the nmap command as a list."""
        xml_path = self.output_dir / f"{output_prefix}.xml"
        normal_path = self.output_dir / f"{output_prefix}.nmap"
        cmd: List[str] = ["nmap"] + extra_args
        cmd += ["-oX", str(xml_path), "-oN", str(normal_path), target]
        return cmd

    def stealth_syn_scan(self, target: str, ports: str = "",
                         timeout: int = 600) -> RunResult:
        """Run a SYN stealth scan.

        When *ports* is empty the port range is read from the active
        profile (``surface.options.port_range``), falling back to
        ``--top-ports 1000``.
        """
        effective_ports = ports or self._default_port_range()
        timing = self._timing_flag()
        # Parse ports argument: could be "--top-ports 1000" or "-p 22,80"
        port_args = effective_ports.split()
        args: List[str] = ["-sS", timing] + port_args + ["-Pn", "--open"]
        args += self._extra_timing_args()
        cmd = self._base_cmd(args, target, "stealth_syn")
        effective_timeout = self.tool_cfg.mode_timeout("stealth_syn", timeout)
        self.logger.command(" ".join(cmd))
        return self.runner.run(cmd, timeout=effective_timeout)

    def service_version_scan(self, target: str, ports: str = "",
                             timeout: int = 600) -> RunResult:
        """Run a service/version detection scan."""
        timing = self._timing_flag()
        args: List[str] = ["-sV", timing]
        if ports:
            args += ports.split()
        args += ["-Pn", "--open"]
        args += self._extra_timing_args()
        cmd = self._base_cmd(args, target, "service_version")
        effective_timeout = self.tool_cfg.mode_timeout("service_version", timeout)
        self.logger.command(" ".join(cmd))
        return self.runner.run(cmd, timeout=effective_timeout)

    def get_xml_path(self, prefix: str = "stealth_syn") -> Path:
        """Return path to XML output file."""
        return self.output_dir / f"{prefix}.xml"

    def get_nmap_path(self, prefix: str = "stealth_syn") -> Path:
        """Return path to normal output file."""
        return self.output_dir / f"{prefix}.nmap"
