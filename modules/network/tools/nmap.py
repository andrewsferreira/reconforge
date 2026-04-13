"""ReconForge Nmap Tool Wrapper - Network scanning and enumeration.

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Profile-aware: when a :class:`ProfileLoader` is provided, timing and
scan options are read from the resolved OPSEC profile.

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


class NmapTool:
    """Wrapper for nmap with structured scan modes."""

    TOOL_NAME = "nmap"

    def __init__(self, runner: Runner, logger, output_dir: Path,
                 opsec_mode: str = "normal",
                 profile: Optional["ProfileLoader"] = None,
                 config: Optional["ConfigLoader"] = None):
        self.runner = runner
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode
        self.profile = profile
        self.tool_cfg = ToolConfig(config, self.TOOL_NAME)

    def is_available(self) -> bool:
        """Check if nmap is installed."""
        return self.runner.check_tool(self.TOOL_NAME)

    def _base_cmd(self, extra_args: List[str], target: str,
                  output_prefix: str, xml_output: bool = True) -> List[str]:
        """Build the nmap command as a list."""
        cmd: List[str] = ["nmap"] + extra_args
        if xml_output:
            xml_path = self.output_dir / f"{output_prefix}.xml"
            normal_path = self.output_dir / f"{output_prefix}.nmap"
            cmd += ["-oX", str(xml_path), "-oN", str(normal_path)]
        cmd.append(target)
        return cmd

    def _timing_flag(self) -> str:
        """Get nmap timing flag from profile or OPSEC mode fallback."""
        if self.profile:
            return f"-{self.profile.nmap_timing}"
        return {
            "stealth": "-T2",
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

    def _port_range(self) -> str:
        """Return the port range from profile or default all-ports."""
        if self.profile:
            pr = self.profile.get("scanning.port_range")
            if pr:
                return str(pr)
        return "-"

    def ping_sweep(self, target: str, timeout: int = 120) -> RunResult:
        """Host discovery with ping sweep (-sn)."""
        self.logger.info(f"Running ping sweep on {target}")
        timing = self._timing_flag()
        effective_timeout = self.tool_cfg.mode_timeout("ping_sweep", timeout)
        cmd = self._base_cmd(["-sn", timing] + self._extra_timing_args(),
                             target, "ping_sweep")
        return self.runner.run(cmd, timeout=effective_timeout)

    def syn_scan(self, target: str, ports: str = "",
                 timeout: int = 600) -> RunResult:
        """SYN stealth scan (-sS)."""
        effective_ports = ports or self._port_range()
        self.logger.info(f"Running SYN scan on {target} ports={effective_ports}")
        timing = self._timing_flag()
        effective_timeout = self.tool_cfg.mode_timeout("syn_scan", timeout)
        cmd = self._base_cmd(
            ["-sS", "-p", effective_ports, timing, "--open"]
            + self._extra_timing_args(),
            target, "syn_scan",
        )
        return self.runner.run(cmd, timeout=effective_timeout)

    def connect_scan(self, target: str, ports: str = "",
                     timeout: int = 600) -> RunResult:
        """TCP connect scan (-sT) for unprivileged users."""
        effective_ports = ports or self._port_range()
        self.logger.info(f"Running connect scan on {target} ports={effective_ports}")
        timing = self._timing_flag()
        effective_timeout = self.tool_cfg.mode_timeout("connect_scan", timeout)
        cmd = self._base_cmd(
            ["-sT", "-p", effective_ports, timing, "--open"]
            + self._extra_timing_args(),
            target, "connect_scan",
        )
        return self.runner.run(cmd, timeout=effective_timeout)

    def version_scan(self, target: str, ports: str = "",
                     timeout: int = 600) -> RunResult:
        """Service version detection (-sV)."""
        self.logger.info(f"Running version scan on {target}")
        timing = self._timing_flag()
        effective_timeout = self.tool_cfg.mode_timeout("version_scan", timeout)
        args: List[str] = ["-sV"]
        if ports:
            args += ["-p", ports]
        args += [timing, "--open", "--version-intensity", "5"]
        args += self._extra_timing_args()
        cmd = self._base_cmd(args, target, "version_scan")
        return self.runner.run(cmd, timeout=effective_timeout)

    def script_scan(self, target: str, ports: str = "",
                    scripts: str = "",
                    timeout: int = 900) -> RunResult:
        """NSE script scan (--script)."""
        if not scripts and self.profile:
            scripts = self.profile.get("scanning.script_categories", "default,vuln")
        scripts = scripts or "default,vuln"
        self.logger.info(f"Running script scan on {target} scripts={scripts}")
        timing = self._timing_flag()
        effective_timeout = self.tool_cfg.mode_timeout("script_scan", timeout)
        args: List[str] = ["-sC", "-sV"]
        if ports:
            args += ["-p", ports]
        args += [timing, f"--script={scripts}"]
        args += self._extra_timing_args()
        cmd = self._base_cmd(args, target, "script_scan")
        return self.runner.run(cmd, timeout=effective_timeout)

    def aggressive_scan(self, target: str, ports: str = "",
                        timeout: int = 1200) -> RunResult:
        """Aggressive scan with OS detection, versions, scripts, traceroute."""
        self.logger.info(f"Running aggressive scan on {target}")
        effective_timeout = self.tool_cfg.mode_timeout("aggressive_scan", timeout)
        args: List[str] = ["-A"]
        if ports:
            args += ["-p", ports]
        args += ["-T4", "--open"]
        cmd = self._base_cmd(args, target, "aggressive_scan")
        return self.runner.run(cmd, timeout=effective_timeout)

    def udp_scan(self, target: str, ports: str = "",
                 timeout: int = 600) -> RunResult:
        """UDP scan for common services."""
        _DEFAULT_UDP = ("53,67,68,69,111,123,135,137,138,139,161,162,"
                        "445,500,514,520,631,1434,1900,4500,5353,49152")
        if not ports and self.profile:
            ports = self.profile.get("scanning.udp_ports", _DEFAULT_UDP)
        ports = ports or _DEFAULT_UDP
        self.logger.info(f"Running UDP scan on {target}")
        timing = self._timing_flag()
        effective_timeout = self.tool_cfg.mode_timeout("udp_scan", timeout)
        cmd = self._base_cmd(
            ["-sU", "-p", ports, timing, "--open"]
            + self._extra_timing_args(),
            target, "udp_scan",
        )
        return self.runner.run(cmd, timeout=effective_timeout)

    def quick_scan(self, target: str, timeout: int = 300) -> RunResult:
        """Quick scan of top 1000 ports with version detection."""
        self.logger.info(f"Running quick scan on {target}")
        timing = self._timing_flag()
        effective_timeout = self.tool_cfg.mode_timeout("quick_scan", timeout)
        cmd = self._base_cmd(
            ["-sV", "-sC", timing, "--open"] + self._extra_timing_args(),
            target, "quick_scan",
        )
        return self.runner.run(cmd, timeout=effective_timeout)

    def smb_scripts(self, target: str, timeout: int = 300) -> RunResult:
        """Run SMB-specific NSE scripts."""
        self.logger.info(f"Running SMB scripts on {target}")
        scripts = "smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-vuln*"
        effective_timeout = self.tool_cfg.mode_timeout("smb_scripts", timeout)
        cmd = self._base_cmd(
            ["-p", "139,445", f"--script={scripts}"], target, "smb_scripts"
        )
        return self.runner.run(cmd, timeout=effective_timeout)

    def get_xml_path(self, scan_name: str) -> Path:
        """Get the XML output path for a scan."""
        return self.output_dir / f"{scan_name}.xml"
