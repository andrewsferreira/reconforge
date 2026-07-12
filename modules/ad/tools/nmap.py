"""ReconForge AD - Nmap Tool Wrapper for AD-specific scanning.

AD-focused nmap scans using LDAP, SMB, and Kerberos NSE scripts.

All commands are built as structured argument lists (list[str]) to
prevent shell injection and improve reliability.

Config-aware: when a :class:`ConfigLoader` is provided, timeouts and
scan profile arguments are read from ``tools.yaml``.

Author: Andrews Ferreira
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from core.runner import Runner, RunResult
from core.tool_config import ToolConfig

if TYPE_CHECKING:
    from core.config_loader import ConfigLoader
    from core.profile_loader import ProfileLoader


class ADNmapTool:
    """Wrapper for nmap with AD-specific scan profiles."""

    TOOL_NAME = "nmap"
    TOOL_CONFIG_KEY = "nmap_ad"

    # NSE scripts relevant to AD enumeration
    LDAP_SCRIPTS = "ldap-rootdse,ldap-search"
    SMB_SCRIPTS = "smb-security-mode,smb-os-discovery,smb-enum-shares,smb-enum-users,smb2-security-mode"
    KERBEROS_SCRIPTS = "krb5-enum-users"
    ALL_AD_SCRIPTS = f"{LDAP_SCRIPTS},{SMB_SCRIPTS},{KERBEROS_SCRIPTS}"

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
        return self.runner.check_tool(self.TOOL_NAME)

    # ------------------------------------------------------------------
    # Scan methods
    # ------------------------------------------------------------------

    def ad_service_scan(self, target: str, timeout: int = 300) -> RunResult:
        """Scan common AD ports with version detection."""
        self.logger.info(f"Running AD service scan on {target}")
        timing = self._timing_flag()
        ports = "53,88,135,139,389,445,464,593,636,3268,3269,5985,5986,9389"
        out_xml = self.output_dir / "nmap_ad_services.xml"
        out_nmap = self.output_dir / "nmap_ad_services.nmap"
        effective_timeout = self.tool_cfg.mode_timeout("ad_service_scan", timeout)
        cmd: List[str] = [
            "nmap", "-sV", "-sC", "-p", ports, timing, "--open",
            "-oX", str(out_xml), "-oN", str(out_nmap), target,
        ]
        return self.runner.run(cmd, timeout=effective_timeout)

    def ldap_scripts(self, target: str, timeout: int = 120) -> RunResult:
        """Run LDAP-specific NSE scripts."""
        self.logger.info(f"Running LDAP NSE scripts on {target}")
        out_xml = self.output_dir / "nmap_ldap.xml"
        out_nmap = self.output_dir / "nmap_ldap.nmap"
        effective_timeout = self.tool_cfg.mode_timeout("ldap_scripts", timeout)
        cmd: List[str] = [
            "nmap", "-p", "389,636,3268,3269",
            f"--script={self.LDAP_SCRIPTS}",
            "-oX", str(out_xml), "-oN", str(out_nmap), target,
        ]
        return self.runner.run(cmd, timeout=effective_timeout)

    def smb_scripts(self, target: str, timeout: int = 120) -> RunResult:
        """Run SMB-specific NSE scripts."""
        self.logger.info(f"Running SMB NSE scripts on {target}")
        out_xml = self.output_dir / "nmap_smb.xml"
        out_nmap = self.output_dir / "nmap_smb.nmap"
        effective_timeout = self.tool_cfg.mode_timeout("smb_scripts", timeout)
        cmd: List[str] = [
            "nmap", "-p", "139,445",
            f"--script={self.SMB_SCRIPTS}",
            "-oX", str(out_xml), "-oN", str(out_nmap), target,
        ]
        return self.runner.run(cmd, timeout=effective_timeout)

    def kerberos_scan(self, target: str, timeout: int = 60) -> RunResult:
        """Detect Kerberos service (port 88)."""
        self.logger.info(f"Scanning Kerberos (port 88) on {target}")
        out_xml = self.output_dir / "nmap_kerberos.xml"
        out_nmap = self.output_dir / "nmap_kerberos.nmap"
        effective_timeout = self.tool_cfg.mode_timeout("kerberos_scan", timeout)
        cmd: List[str] = [
            "nmap", "-sV", "-p", "88", "--open",
            "-oX", str(out_xml), "-oN", str(out_nmap), target,
        ]
        return self.runner.run(cmd, timeout=effective_timeout)

    def full_ad_scripts(self, target: str, timeout: int = 600) -> RunResult:
        """Run all AD-related NSE scripts."""
        self.logger.info(f"Running full AD NSE scan on {target}")
        timing = self._timing_flag()
        ports = "53,88,135,139,389,445,464,636,3268,3269,5985,5986"
        out_xml = self.output_dir / "nmap_ad_full.xml"
        out_nmap = self.output_dir / "nmap_ad_full.nmap"
        effective_timeout = self.tool_cfg.mode_timeout("full_ad_scripts", timeout)
        cmd: List[str] = [
            "nmap", "-sV", "-p", ports, timing, "--open",
            f"--script={self.ALL_AD_SCRIPTS}",
            "-oX", str(out_xml), "-oN", str(out_nmap), target,
        ]
        return self.runner.run(cmd, timeout=effective_timeout)

    # ------------------------------------------------------------------
    # DNS enumeration
    # ------------------------------------------------------------------

    def dns_srv_lookup(self, domain: str, target: str,
                       timeout: int = 30) -> RunResult:
        """Query DNS SRV records for domain controllers."""
        self.logger.info(f"DNS SRV lookup for DCs in {domain} via {target}")
        out = self.output_dir / "dns_srv_dc.txt"
        effective_timeout = self.tool_cfg.mode_timeout("dns_srv", timeout)
        cmd: List[str] = [
            "dig", f"@{target}",
            f"_ldap._tcp.dc._msdcs.{domain}", "SRV", "+short",
        ]
        return self.runner.run(cmd, timeout=effective_timeout, output_file=out)

    def dns_all_srv(self, domain: str, target: str,
                    timeout: int = 60) -> RunResult:
        """Query multiple AD-related SRV records."""
        self.logger.info(f"DNS SRV enumeration for {domain}")
        out = self.output_dir / "dns_srv_all.txt"
        effective_timeout = self.tool_cfg.mode_timeout("dns_srv", timeout)
        records = [
            f"_ldap._tcp.dc._msdcs.{domain}",
            f"_kerberos._tcp.{domain}",
            f"_gc._tcp.{domain}",
            f"_kpasswd._tcp.{domain}",
        ]
        combined_stdout = ""
        results: List[RunResult] = []
        for record in records:
            cmd: List[str] = [
                "dig", f"@{target}", record, "SRV", "+short",
            ]
            result = self.runner.run(cmd, timeout=effective_timeout)
            combined_stdout += f";; {record}\n{result.stdout}\n"
            results.append(result)

        # Write combined output
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(combined_stdout)

        if not results:
            return RunResult(
                command="dig (dns_all_srv)", returncode=0,
                stdout=combined_stdout, stderr="", duration=0.0,
                success=True, output_file=str(out),
            )

        # Overall success reflects whether every dig call actually executed
        # (an empty SRV answer is still returncode 0 — success is about
        # command execution, not record presence). A single failed dig
        # call (server unreachable, binary missing, etc.) must not be
        # silently reported as an overall success.
        all_succeeded = all(r.success for r in results)
        first_failure = next((r for r in results if not r.success), None)
        last_result = results[-1]
        return RunResult(
            command="dig (dns_all_srv)",
            returncode=last_result.returncode if all_succeeded else first_failure.returncode,
            stdout=combined_stdout,
            stderr="\n".join(r.stderr for r in results if r.stderr),
            duration=sum(r.duration for r in results),
            success=all_succeeded,
            output_file=str(out),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _timing_flag(self) -> str:
        """Get nmap timing flag from profile or OPSEC mode fallback."""
        if self.profile:
            return f"-{self.profile.nmap_timing}"
        return {
            "stealth": "-T2",
            "normal": "-T3",
            "aggressive": "-T4",
        }.get(self.opsec_mode, "-T3")

    def get_xml_path(self, scan_name: str) -> Path:
        return self.output_dir / f"{scan_name}.xml"
