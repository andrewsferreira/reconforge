"""ReconForge Network Module - Main orchestrator for network reconnaissance.

Orchestrates the four-phase network recon kill chain:
1. Host Discovery - Find live hosts on the network
2. Port Scanning - Enumerate open ports and services
3. Service Enumeration - Deep dive into SMB, LDAP, etc.
4. Authentication Checks - Test for weak/default credentials

Usage:
    module = NetworkModule(target="10.10.10.1", output_base="outputs")
    module.run()                          # Full scan
    module.run(phases=["discovery"])       # Single phase
    module.run(opsec_mode="stealth")      # Stealth mode
    module.run(brute_force=True)          # Enable hydra (opt-in)
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.authorization_gate import ScopeAuthorization

from core.logger import ReconLogger
from core.runner import Runner
from core.config_loader import ConfigLoader
from core.output_manager import OutputManager
from core.attack_workflow import AttackWorkflow
from core.loot_manager import LootManager
from core.findings_manager import FindingsManager
from core.notes_manager import NotesManager
from core.opsec_checks import OpsecChecker
from core.target_parser import parse_target
from core.profile_loader import ProfileLoader
from core.telemetry import ModuleTelemetry
from core.data_contracts import SCHEMA_VERSION, build_contract

from modules.network.tools.nmap import NmapTool
from modules.network.tools.enum4linux import Enum4linuxTool
from modules.network.tools.smbclient import SmbclientTool
from modules.network.tools.ldapsearch import LdapsearchTool
from modules.network.tools.hydra import HydraTool

from modules.network.parsers.nmap_parser import NmapParser
from modules.network.parsers.enum4linux_parser import Enum4linuxParser
from modules.network.parsers.smb_parser import SmbParser
from modules.network.parsers.ldap_parser import LdapParser

from modules.network.phases.host_discovery import HostDiscoveryPhase
from modules.network.phases.port_scanning import PortScanningPhase
from modules.network.phases.service_enumeration import ServiceEnumerationPhase
from modules.network.phases.authentication_checks import AuthenticationChecksPhase


class NetworkModule:
    """Main orchestrator for the Network reconnaissance module.

    Coordinates tool execution, parsing, finding generation, loot
    extraction, and attack workflow tracking across all four phases.

    Attributes:
        target: Target specification (IP, hostname, or CIDR).
        opsec_mode: OPSEC profile (stealth, normal, aggressive).
        brute_force: Whether hydra testing is authorized.
    """

    MODULE_NAME = "network"
    VALID_PHASES = ["discovery", "scanning", "enumeration", "authentication"]

    def __init__(self, target: str, output_base: str = "outputs",
                 opsec_mode: str = "normal", verbose: bool = False,
                 dry_run: bool = False, timeout: int = 600,
                 config_dir: Optional[str] = None,
                 encrypt_loot: bool = False,
                 scope: Optional["ScopeAuthorization"] = None,
                 approval_id: Optional[str] = None):
        """Initialize the Network module.

        Args:
            target: Target IP, hostname, or CIDR range.
            output_base: Base directory for all outputs.
            opsec_mode: OPSEC mode (stealth, normal, aggressive).
            verbose: Enable verbose/debug logging.
            dry_run: If True, log commands without executing.
            timeout: Default timeout for commands.
            config_dir: Path to config directory.
            encrypt_loot: Encrypt loot files with Fernet.
            scope: Optional authorized-scope document (--enforce-scope);
                propagated to the Runner so every command execution is
                re-checked against it, not just the initial CLI gate.
            approval_id: Approval id to check against *scope*.
        """
        self._encrypt_loot = encrypt_loot
        self.target_str = target
        self.target = parse_target(target)
        self.opsec_mode = opsec_mode
        self.credential_vault = None  # Set by WorkflowOrchestrator

        self.output = OutputManager(base_dir=output_base, target=target)
        self.execution_id = f"run_{uuid.uuid4().hex[:12]}"
        # Core services
        self.logger = ReconLogger(
            name="network",
            verbose=verbose,
            log_dir=self.output.module_dir(self.MODULE_NAME),
            execution_id=self.execution_id,
        )
        self.runner = Runner(logger=self.logger, timeout=timeout, dry_run=dry_run,
                              target=target, scope=scope, approval_id=approval_id)
        self.config = ConfigLoader(config_dir=config_dir)
        self.workflow = AttackWorkflow()
        self.loot = LootManager(encrypt=self._encrypt_loot)
        self.findings_mgr = FindingsManager()
        self.notes = NotesManager(target=target)
        self.opsec = OpsecChecker(mode=opsec_mode, logger=self.logger)
        self.telemetry = ModuleTelemetry(self.MODULE_NAME, target, execution_id=self.execution_id)

        # Output directories
        self.raw_dir = self.output.raw_dir(self.MODULE_NAME)
        self.parsed_dir = self.output.parsed_dir(self.MODULE_NAME)
        self.module_dir = self.output.module_dir(self.MODULE_NAME)

        # Profile loader — resolves OPSEC profile for timing, technique
        # toggles, and tool-specific configuration (CF-2 activation).
        self.profile = ProfileLoader(self.config, opsec_mode=opsec_mode, module=self.MODULE_NAME)

        # Initialize tools (profile-aware, config-aware)
        self.nmap = NmapTool(self.runner, self.logger, self.raw_dir, opsec_mode,
                             profile=self.profile, config=self.config)
        self.enum4linux = Enum4linuxTool(self.runner, self.logger, self.raw_dir,
                                        config=self.config)
        self.smbclient = SmbclientTool(self.runner, self.logger, self.raw_dir,
                                      config=self.config)
        self.ldapsearch_tool = LdapsearchTool(self.runner, self.logger, self.raw_dir,
                                             config=self.config)
        self.hydra = HydraTool(self.runner, self.logger, self.raw_dir,
                               authorized=False, config=self.config)

        # Initialize parsers
        self.nmap_parser = NmapParser()
        self.enum4linux_parser = Enum4linuxParser()
        self.smb_parser = SmbParser()
        self.ldap_parser = LdapParser()

        # Shared keyword args for all phases (mirrors Web/API pattern)
        self._phase_kwargs = dict(
            logger=self.logger,
            runner=self.runner,
            config=self.config,
            output_dir=self.parsed_dir,
            findings=self.findings_mgr,
            loot=self.loot,
            workflow=self.workflow,
            notes=self.notes,
            opsec=self.opsec,
            opsec_mode=opsec_mode,
            profile=self.profile,
        )

        # Initialize phases
        self.phase_discovery = HostDiscoveryPhase(
            nmap=self.nmap, parser=self.nmap_parser,
            **self._phase_kwargs,
        )
        self.phase_scanning = PortScanningPhase(
            nmap=self.nmap, parser=self.nmap_parser,
            **self._phase_kwargs,
        )
        self.phase_enumeration = ServiceEnumerationPhase(
            nmap=self.nmap, enum4linux=self.enum4linux,
            smbclient=self.smbclient, ldapsearch=self.ldapsearch_tool,
            nmap_parser=self.nmap_parser, enum4linux_parser=self.enum4linux_parser,
            smb_parser=self.smb_parser, ldap_parser=self.ldap_parser,
            **self._phase_kwargs,
        )
        self.phase_auth = AuthenticationChecksPhase(
            hydra=self.hydra, smbclient=self.smbclient,
            **self._phase_kwargs,
        )

    def run(self, phases: Optional[List[str]] = None,
            brute_force: bool = False) -> Dict[str, Any]:
        """Execute the network reconnaissance workflow.

        Phase selection priority:
        1. Explicit ``phases`` argument (CLI / programmatic).
        2. Profile-driven ``enabled_phases()`` from *profiles.yaml*.
        3. All ``VALID_PHASES`` (default).

        Args:
            phases: List of phases to run. None = profile / all.
            brute_force: Enable hydra brute-force testing.

        Returns:
            Dict with complete scan results.
        """
        if phases:
            phases_to_run = phases
        else:
            profile_phases = self.profile.enabled_phases()
            phases_to_run = profile_phases if profile_phases else list(self.VALID_PHASES)

        # Technique toggles from the profile
        scanning_cfg = self.profile.section("scanning")
        enum_cfg = self.profile.section("enumeration")
        auth_cfg = self.profile.section("authentication")

        # Brute-force requires both opt-in flag AND profile permission
        brute_allowed = auth_cfg.get("brute_force", False) if auth_cfg else False
        self.hydra.authorized = brute_force and brute_allowed if auth_cfg else brute_force

        # Credential vault: ingest available credentials at start
        if self.credential_vault:
            imported = self.credential_vault.ingest_from_loot(self.loot)
            if imported:
                self.logger.info(f"Imported {imported} credentials from vault")

        display = self.target.display
        self.logger.info(f"{'='*60}")
        self.logger.info(f"ReconForge Network Module - Target: {display}")
        self.logger.info(f"OPSEC Mode: {self.opsec_mode} | Profile: {self.profile.opsec_mode} | Brute-force: {brute_force}")
        self.logger.info(f"Phases: {', '.join(phases_to_run)}")
        self.logger.info(f"Output: {self.module_dir}")
        self.logger.info(f"{'='*60}")

        self.notes.add(f"Network module started against {display}", "phase")
        self.notes.add(f"OPSEC mode: {self.opsec_mode}, Brute-force: {brute_force}", "general")

        # Check tool availability
        self._check_tools()

        results: Dict[str, Any] = {
            "target": self.target_str,
            "opsec_mode": self.opsec_mode,
            "schema_version": SCHEMA_VERSION,
            "execution_id": self.execution_id,
            "start_time": datetime.now().isoformat(),
            "phases": {},
        }

        try:
            # Phase 1: Host Discovery
            if "discovery" in phases_to_run:
                discovery_results = self.telemetry.run_phase(
                    "discovery",
                    lambda: self.phase_discovery.run(
                        target=self.target_str,
                        is_network=self.target.is_network,
                    ),
                )
                results["phases"]["discovery"] = discovery_results
                live_hosts = discovery_results.get("live_hosts", [])
            else:
                live_hosts = [self.target.ip or self.target.hostname or self.target_str]

            if not live_hosts:
                self.logger.warning("No live hosts discovered. Stopping.")
                results["error"] = "No live hosts found"
                self._generate_reports(results)
                return results

            # Phase 2: Port Scanning
            if "scanning" in phases_to_run:
                scan_results = self.telemetry.run_phase(
                    "scanning",
                    lambda: self.phase_scanning.run(
                        targets=live_hosts,
                        opsec_mode=self.opsec_mode,
                    ),
                )
                results["phases"]["scanning"] = scan_results
            else:
                scan_results = {"hosts": {}}

            # Phase 3: Service Enumeration
            if "enumeration" in phases_to_run:
                for host in live_hosts:
                    enum_results = self.telemetry.run_phase(
                        f"enumeration:{host}",
                        lambda host=host: self.phase_enumeration.run(
                            target=host,
                            scan_results=scan_results,
                            opsec_mode=self.opsec_mode,
                        ),
                    )
                    results["phases"].setdefault("enumeration", {})[host] = enum_results

            # Phase 4: Authentication Checks
            if "authentication" in phases_to_run:
                for host in live_hosts:
                    auth_results = self.telemetry.run_phase(
                        f"authentication:{host}",
                        lambda host=host: self.phase_auth.run(
                            target=host,
                            scan_results=scan_results,
                            brute_force=brute_force,
                            opsec_mode=self.opsec_mode,
                        ),
                    )
                    results["phases"].setdefault("authentication", {})[host] = auth_results

        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            results["interrupted"] = True
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            results["error"] = str(e)
            raise
        finally:
            results["end_time"] = datetime.now().isoformat()
            results["observability"] = self.telemetry.to_dict(self.runner.get_metrics())
            self._generate_reports(results)

        # Credential vault: contribute discovered credentials at end
        if self.credential_vault:
            contributed = self.credential_vault.ingest_from_loot(self.loot)
            if contributed:
                self.logger.info(f"Contributed {contributed} credentials to vault")

        self._print_summary(results)
        return results

    def _check_tools(self):
        """Check availability of required tools."""
        tools = {
            "nmap": self.nmap.is_available(),
            "enum4linux": self.enum4linux.is_available(),
            "smbclient": self.smbclient.is_available(),
            "ldapsearch": self.ldapsearch_tool.is_available(),
            "hydra": self.hydra.is_available(),
        }

        for tool, available in tools.items():
            if available:
                self.logger.debug(f"Tool available: {tool}")
            else:
                self.logger.warning(f"Tool not found: {tool} (some features will be skipped)")

        self.notes.add(
            f"Tool check: {', '.join(t for t, a in tools.items() if a)} available; "
            f"{', '.join(t for t, a in tools.items() if not a) or 'none'} missing",
            "general"
        )

    def _generate_reports(self, results: Dict):
        """Generate all output reports."""
        self.logger.info("Generating reports...")

        try:
            # findings.json
            self.findings_mgr.save_json(self.output.findings_file(self.MODULE_NAME, "json"))
            self.findings_mgr.save_contract(
                self.output.contract_file(self.MODULE_NAME, "findings"),
                execution_id=self.execution_id,
                module=self.MODULE_NAME,
            )

            # findings.md
            self.findings_mgr.save_markdown(self.output.findings_file(self.MODULE_NAME, "md"))

            # session.md
            self.notes.save(self.output.session_file(self.MODULE_NAME))

            # attack_paths.md
            attack_paths_content = self.workflow.to_markdown()
            self.output.attack_paths_file(self.MODULE_NAME).write_text(attack_paths_content)

            # commands.log
            self.runner.save_command_log(self.output.commands_log(self.MODULE_NAME))

            # loot.json (CF-3: always use LootManager API via OutputManager)
            self.loot.save(self.output.loot_file(self.MODULE_NAME))
            self.loot.save_contract(
                self.output.contract_file(self.MODULE_NAME, "loot"),
                execution_id=self.execution_id,
                module=self.MODULE_NAME,
            )

            # results contract + audit
            results_contract = build_contract(
                "results",
                results,
                execution_id=self.execution_id,
                module=self.MODULE_NAME,
            )
            self.output.contract_file(self.MODULE_NAME, "results").write_text(
                json.dumps(results_contract, indent=2)
            )
            self.output.audit_file(self.MODULE_NAME).write_text(
                json.dumps(results.get("observability", {}), indent=2)
            )
            self.output.write_evidence_manifest(self.MODULE_NAME, self.execution_id)

            # quick_report.md
            self._generate_quick_report(results)

            self.logger.info(f"Reports saved to: {self.module_dir}")

        except Exception as e:
            self.logger.error(f"Error generating reports: {e}")

    def _generate_quick_report(self, results: Dict):
        """Generate executive summary report."""
        report_path = self.output.report_file(self.MODULE_NAME)

        severity_counts = self.findings_mgr.count_by_severity()
        loot_summary = self.loot.summary()
        total_findings = sum(severity_counts.values())

        lines = [
            "# ReconForge Quick Report - Network Module\n",
            f"**Target:** {self.target_str}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**OPSEC Mode:** {self.opsec_mode}",
            f"**Author:** Andrews Ferreira",
            "",
            "## Executive Summary\n",
            f"Network reconnaissance of **{self.target_str}** identified "
            f"**{total_findings}** findings:\n",
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "⚪")
            lines.append(f"- {icon} **{sev.upper()}:** {count}")

        lines.append("")
        lines.append("## Loot Summary\n")
        for ltype, count in loot_summary.items():
            lines.append(f"- **{ltype}:** {count} item(s)")

        # Critical and high findings detail
        critical_high = (
            self.findings_mgr.get_by_severity("critical") +
            self.findings_mgr.get_by_severity("high")
        )
        if critical_high:
            lines.append("\n## Critical & High Findings\n")
            for f in critical_high:
                lines.append(f"### [{f.severity.upper()}] {f.description}")
                lines.append(f"- **Target:** {f.target}")
                lines.append(f"- **Confidence:** {f.confidence}")
                if f.recommendation:
                    lines.append(f"- **Recommendation:** {f.recommendation}")
                lines.append("")

        # Attack paths
        if self.workflow.attack_paths:
            lines.append("## Identified Attack Paths\n")
            for path in self.workflow.attack_paths:
                lines.append(f"### {path.name} [{path.risk.upper()}]")
                lines.append(f"{path.description}\n")
                for i, step in enumerate(path.steps, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")

        # Next steps
        suggestions = self.workflow.get_suggestions()
        if suggestions:
            lines.append("## Suggested Next Steps\n")
            for s in suggestions[:10]:
                lines.append(f"- [{s['priority'].upper()}] `{s['command']}`")
                lines.append(f"  - {s['justification']}")

        lines.append(f"\n---\n*Generated by ReconForge v1.0 release on {datetime.now():%Y-%m-%d %H:%M:%S}*\n")

        report_path.write_text("\n".join(lines))

    def _print_summary(self, results: Dict):
        """Print a summary to console."""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("SCAN COMPLETE - Summary")
        self.logger.info(f"{'='*60}")

        severity_counts = self.findings_mgr.count_by_severity()
        total = sum(severity_counts.values())
        self.logger.info(f"Total findings: {total}")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count:
                self.logger.info(f"  {sev.upper()}: {count}")

        loot_summary = self.loot.summary()
        if loot_summary:
            self.logger.info(f"Loot: {loot_summary}")

        if self.workflow.attack_paths:
            self.logger.info(f"Attack paths: {len(self.workflow.attack_paths)}")

        self.logger.info(f"Output: {self.module_dir}")
        self.logger.info(f"{'='*60}")
