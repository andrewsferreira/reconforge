"""ReconForge AD Module - Main orchestrator for Active Directory reconnaissance.

Author: Andrews Ferreira

Orchestrates the five-phase AD recon kill chain:
1. Passive Recon - Service discovery, anonymous access tests, DNS SRV enumeration
2. Identity Enumeration - Users, groups, computers, SPNs, AS-REP roastable accounts
3. Configuration Enumeration - Password policies, trusts, GPOs, shares, DCs
4. Delegation Discovery - Unconstrained, constrained, and RBCD delegation enumeration
5. Bloodhound Collection - AD graph data collection for attack path analysis

Modular architecture (v2):
    collectors → analyzers → attack_paths → reporting
    Phases are thin orchestration layers that delegate to these packages.

Usage:
    module = ADModule(target="10.10.10.1", domain="corp.local")
    module.run()                                # Full scan
    module.run(phases=["passive"])              # Single phase
    module.run(opsec_mode="stealth")           # Stealth mode
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

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

from modules.ad.tools.enum4linux_ng import Enum4linuxNgTool
from modules.ad.tools.ldapsearch import ADLdapsearchTool
from modules.ad.tools.smbclient import ADSmbclientTool
from modules.ad.tools.impacket import ImpacketTool
from modules.ad.tools.nmap import ADNmapTool
from modules.ad.tools.bloodhound import BloodhoundTool
from modules.ad.tools.netexec import NetexecTool
from modules.ad.tools.advanced_impacket import AdvancedImpacketTool

from modules.ad.parsers.enum4linux_ng_parser import Enum4linuxNgParser
from modules.ad.parsers.ldap_parser import ADLdapParser
from modules.ad.parsers.smb_parser import ADSmbParser
from modules.ad.parsers.impacket_parser import ImpacketParser
from modules.ad.parsers.nmap_parser import ADNmapParser
from modules.ad.parsers.bloodhound_parser import BloodhoundParser
from modules.ad.parsers.netexec_parser import NetexecParser
from modules.ad.parsers.delegation_parser import DelegationParser

from modules.ad.phases.passive_recon import PassiveReconPhase
from modules.ad.phases.identity_enumeration import IdentityEnumerationPhase
from modules.ad.phases.configuration_enumeration import ConfigurationEnumerationPhase
from modules.ad.phases.delegation_discovery import DelegationDiscoveryPhase
from modules.ad.phases.bloodhound_collection import BloodhoundCollectionPhase

from modules.ad.reporting import (
    AttackSurfaceReporter, HighValueTargetsReporter,
    AttackPathReporter, RemediationReporter, ADSummaryReporter,
    build_attack_surface_data, build_hvt_data,
    build_path_data, build_remediation_data, build_ad_summary_data,
)


class ADModule:
    """Main orchestrator for the Active Directory reconnaissance module.

    Coordinates tool execution, parsing, finding generation, loot
    extraction, and attack workflow tracking across all five AD phases.
    """

    MODULE_NAME = "ad"
    VALID_PHASES = ["passive", "identity", "configuration", "delegation", "bloodhound"]

    def __init__(self, target: str, domain: str = "",
                 output_base: str = "outputs",
                 opsec_mode: str = "normal", verbose: bool = False,
                 dry_run: bool = False, timeout: int = 600,
                 config_dir: Optional[str] = None,
                 username: str = "", password: str = "",
                 dc_ip: str = "",
                 encrypt_loot: bool = False):
        self.target_str = target
        self.target = parse_target(target)
        self.domain = domain
        self.opsec_mode = opsec_mode
        self.username = username
        self.password = password
        self.dc_ip = dc_ip or target
        self.credential_vault = None  # Set by WorkflowOrchestrator

        self.output = OutputManager(base_dir=output_base, target=target)
        self.execution_id = f"run_{uuid.uuid4().hex[:12]}"
        # Core services
        self.logger = ReconLogger(
            name="ad",
            verbose=verbose,
            log_dir=self.output.module_dir(self.MODULE_NAME),
            execution_id=self.execution_id,
        )
        self.runner = Runner(logger=self.logger, timeout=timeout, dry_run=dry_run)
        self.config = ConfigLoader(config_dir=config_dir)
        self.workflow = AttackWorkflow()
        self.loot = LootManager(encrypt=encrypt_loot)
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

        # Initialize tools (profile-aware)
        self._init_tools()

        # Initialize parsers
        self._init_parsers()

        # Shared phase kwargs
        self._phase_kwargs = dict(
            logger=self.logger, runner=self.runner, config=self.config,
            output_dir=self.parsed_dir, findings=self.findings_mgr,
            loot=self.loot, workflow=self.workflow, notes=self.notes,
            opsec=self.opsec, opsec_mode=opsec_mode,
            profile=self.profile,
        )

        # Initialize phases
        self._init_phases()

        # Initialize reporters
        self.attack_surface_reporter = AttackSurfaceReporter()
        self.hvt_reporter = HighValueTargetsReporter()
        self.attack_path_reporter = AttackPathReporter()
        self.remediation_reporter = RemediationReporter()
        self.ad_summary_reporter = ADSummaryReporter()

    def _init_tools(self) -> None:
        """Initialize tool wrappers (profile-aware, config-aware)."""
        self.enum4linux_ng = Enum4linuxNgTool(self.runner, self.logger, self.raw_dir,
                                             config=self.config)
        self.ldapsearch_tool = ADLdapsearchTool(self.runner, self.logger, self.raw_dir,
                                               config=self.config)
        self.smbclient = ADSmbclientTool(self.runner, self.logger, self.raw_dir,
                                        config=self.config)
        self.impacket = ImpacketTool(self.runner, self.logger, self.raw_dir,
                                    config=self.config)
        self.nmap = ADNmapTool(self.runner, self.logger, self.raw_dir, self.opsec_mode,
                               profile=self.profile, config=self.config)
        self.bloodhound = BloodhoundTool(self.runner, self.logger, self.raw_dir,
                                        config=self.config)
        self.netexec = NetexecTool(self.runner, self.logger, self.raw_dir,
                                  config=self.config)
        self.advanced_impacket = AdvancedImpacketTool(self.runner, self.logger, self.raw_dir,
                                                     config=self.config)

    def _init_parsers(self) -> None:
        """Initialize parser instances."""
        self.enum4linux_ng_parser = Enum4linuxNgParser()
        self.ldap_parser = ADLdapParser()
        self.smb_parser = ADSmbParser()
        self.impacket_parser = ImpacketParser()
        self.nmap_parser = ADNmapParser()
        self.bloodhound_parser = BloodhoundParser()
        self.netexec_parser = NetexecParser()
        self.delegation_parser = DelegationParser()

    def _init_phases(self) -> None:
        """Initialize phase instances."""
        self.phase_passive = PassiveReconPhase(
            nmap=self.nmap, ldapsearch=self.ldapsearch_tool,
            smbclient=self.smbclient, enum4linux_ng=self.enum4linux_ng,
            nmap_parser=self.nmap_parser, ldap_parser=self.ldap_parser,
            smb_parser=self.smb_parser,
            enum4linux_ng_parser=self.enum4linux_ng_parser,
            **self._phase_kwargs,
        )
        self.phase_identity = IdentityEnumerationPhase(
            ldapsearch=self.ldapsearch_tool, enum4linux_ng=self.enum4linux_ng,
            impacket=self.impacket, smbclient=self.smbclient,
            ldap_parser=self.ldap_parser,
            enum4linux_ng_parser=self.enum4linux_ng_parser,
            impacket_parser=self.impacket_parser,
            **self._phase_kwargs,
        )
        self.phase_configuration = ConfigurationEnumerationPhase(
            ldapsearch=self.ldapsearch_tool, smbclient=self.smbclient,
            enum4linux_ng=self.enum4linux_ng, ldap_parser=self.ldap_parser,
            smb_parser=self.smb_parser,
            enum4linux_ng_parser=self.enum4linux_ng_parser,
            **self._phase_kwargs,
        )
        self.phase_delegation = DelegationDiscoveryPhase(
            ldapsearch=self.ldapsearch_tool,
            advanced_impacket=self.advanced_impacket,
            netexec=self.netexec, ldap_parser=self.ldap_parser,
            delegation_parser=self.delegation_parser,
            **self._phase_kwargs,
        )
        self.phase_bloodhound = BloodhoundCollectionPhase(
            bloodhound=self.bloodhound, netexec=self.netexec,
            bloodhound_parser=self.bloodhound_parser,
            netexec_parser=self.netexec_parser,
            **self._phase_kwargs,
        )

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self, phases: Optional[List[str]] = None) -> Dict[str, Any]:
        """Execute the AD reconnaissance workflow.

        Phase selection priority:
        1. Explicit ``phases`` argument (CLI / programmatic).
        2. Profile-driven ``enabled_phases()`` from *profiles.yaml*.
        3. All ``VALID_PHASES`` (default).
        """
        if phases:
            phases_to_run = phases
        else:
            profile_phases = self.profile.enabled_phases()
            phases_to_run = profile_phases if profile_phases else list(self.VALID_PHASES)

        # Credential vault: ingest available credentials at start
        if self.credential_vault:
            imported = self.credential_vault.ingest_from_loot(self.loot)
            if imported:
                self.logger.info(f"Imported {imported} credentials from vault")

        display = self.target.display
        has_creds = bool(self.username and self.password)

        self.logger.info(f"{'='*60}")
        self.logger.info(f"ReconForge AD Module - Target: {display}")
        self.logger.info(f"Domain: {self.domain or 'N/A'} | DC: {self.dc_ip}")
        self.logger.info(f"OPSEC Mode: {self.opsec_mode} | Profile: {self.profile.opsec_mode} | Authenticated: {has_creds}")
        self.logger.info(f"Phases: {', '.join(phases_to_run)}")
        self.logger.info(f"Output: {self.module_dir}")
        self.logger.info(f"{'='*60}")

        self.notes.add(
            f"AD module started against {display} "
            f"(domain={self.domain}, dc={self.dc_ip})", "phase",
        )
        self._check_tools()

        results: Dict[str, Any] = {
            "target": self.target_str, "domain": self.domain,
            "dc_ip": self.dc_ip, "opsec_mode": self.opsec_mode,
            "authenticated": has_creds,
            "schema_version": SCHEMA_VERSION,
            "execution_id": self.execution_id,
            "start_time": datetime.now().isoformat(),
            "phases": {},
        }

        try:
            self._run_phases(phases_to_run, results)
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

        # Credential vault: contribute discovered credentials
        if self.credential_vault:
            contributed = self.credential_vault.ingest_from_loot(self.loot)
            if contributed:
                self.logger.info(f"Contributed {contributed} credentials to vault")

        self._print_summary(results)
        return results

    def _run_phases(self, phases_to_run: List[str], results: Dict) -> None:
        """Execute requested phases sequentially."""
        if "passive" in phases_to_run:
            self.logger.info(f"\n{'─'*60}\nPhase 1: Passive Reconnaissance\n{'─'*60}")
            passive = self.telemetry.run_phase(
                "passive",
                lambda: self.phase_passive.run(
                    target=self.target_str, domain=self.domain,
                    opsec_mode=self.opsec_mode,
                ),
            )
            results["phases"]["passive"] = passive
            if not self.domain and passive.get("domain"):
                self.domain = passive["domain"]
                self.logger.info(f"Discovered domain: {self.domain}")

        if "identity" in phases_to_run:
            self.logger.info(f"\n{'─'*60}\nPhase 2: Identity Enumeration\n{'─'*60}")
            pd = results.get("phases", {}).get("passive", {})
            results["phases"]["identity"] = self.telemetry.run_phase(
                "identity",
                lambda: self.phase_identity.run(
                    target=self.target_str, domain=self.domain,
                    base_dn=pd.get("base_dn", ""),
                    anonymous_ldap=pd.get("anonymous_ldap", False),
                    null_session=pd.get("null_session", False),
                    username=self.username, password=self.password,
                    opsec_mode=self.opsec_mode,
                ),
            )

        if "configuration" in phases_to_run:
            self.logger.info(f"\n{'─'*60}\nPhase 3: Configuration Enumeration\n{'─'*60}")
            pd = results.get("phases", {}).get("passive", {})
            results["phases"]["configuration"] = self.telemetry.run_phase(
                "configuration",
                lambda: self.phase_configuration.run(
                    target=self.target_str, domain=self.domain,
                    base_dn=pd.get("base_dn", ""),
                    anonymous_ldap=pd.get("anonymous_ldap", False),
                    null_session=pd.get("null_session", False),
                    username=self.username, password=self.password,
                    opsec_mode=self.opsec_mode,
                ),
            )

        if "delegation" in phases_to_run:
            self.logger.info(f"\n{'─'*60}\nPhase 4: Delegation Discovery\n{'─'*60}")
            pd = results.get("phases", {}).get("passive", {})
            results["phases"]["delegation"] = self.telemetry.run_phase(
                "delegation",
                lambda: self.phase_delegation.run(
                    target=self.target_str, domain=self.domain,
                    base_dn=pd.get("base_dn", ""),
                    username=self.username, password=self.password,
                    opsec_mode=self.opsec_mode,
                ),
            )

        if "bloodhound" in phases_to_run:
            self.logger.info(f"\n{'─'*60}\nPhase 5: Bloodhound Collection\n{'─'*60}")
            if not (self.username and self.password):
                self.logger.warning("Bloodhound requires credentials. Skipping.")
            else:
                results["phases"]["bloodhound"] = self.telemetry.run_phase(
                    "bloodhound",
                    lambda: self.phase_bloodhound.run(
                        target=self.target_str, domain=self.domain,
                        username=self.username, password=self.password,
                        dc_ip=self.dc_ip, opsec_mode=self.opsec_mode,
                    ),
                )

    # ------------------------------------------------------------------
    # Tool check
    # ------------------------------------------------------------------

    def _check_tools(self) -> None:
        """Check availability of required tools."""
        tools = {
            "nmap": self.nmap.is_available(),
            "enum4linux-ng": self.enum4linux_ng.is_available(),
            "ldapsearch": self.ldapsearch_tool.is_available(),
            "smbclient": self.smbclient.is_available(),
            "impacket": self.impacket.is_available(),
            "bloodhound-python": self.bloodhound.is_available(),
            "netexec": self.netexec.is_available(),
            "advanced-impacket": self.advanced_impacket.is_available(),
        }
        for tool, available in tools.items():
            if available:
                self.logger.debug(f"Tool available: {tool}")
            else:
                self.logger.warning(f"Tool not found: {tool} (some features will be skipped)")

        self.notes.add(
            f"Tool check: "
            f"{', '.join(t for t, a in tools.items() if a)} available; "
            f"{', '.join(t for t, a in tools.items() if not a) or 'none'} missing",
            "general",
        )

    # ------------------------------------------------------------------
    # Report generation (delegates to reporting package)
    # ------------------------------------------------------------------

    def _generate_reports(self, results: Dict) -> None:
        """Generate all output reports via the reporting package."""
        self.logger.info("Generating reports...")
        try:
            # Core reports
            self.findings_mgr.save_json(self.output.findings_file(self.MODULE_NAME, "json"))
            self.findings_mgr.save_contract(
                self.output.contract_file(self.MODULE_NAME, "findings"),
                execution_id=self.execution_id,
                module=self.MODULE_NAME,
            )
            self.findings_mgr.save_markdown(self.output.findings_file(self.MODULE_NAME, "md"))
            self.notes.save(self.output.session_file(self.MODULE_NAME))
            self.output.attack_paths_file(self.MODULE_NAME).write_text(
                self.workflow.to_markdown()
            )
            self.runner.save_command_log(self.output.commands_log(self.MODULE_NAME))
            self.loot.save(self.output.loot_file(self.MODULE_NAME))
            self.loot.save_contract(
                self.output.contract_file(self.MODULE_NAME, "loot"),
                execution_id=self.execution_id,
                module=self.MODULE_NAME,
            )

            # Attack surface / quick report
            report_data = build_attack_surface_data(
                self.target_str, self.domain, self.dc_ip, self.opsec_mode,
                self.username, self.findings_mgr, self.loot, self.workflow,
            )
            self.attack_surface_reporter.save(
                self.attack_surface_reporter.generate(report_data),
                self.output.report_file(self.MODULE_NAME),
            )

            # High-value targets
            hvt_data = build_hvt_data(results, self.domain, self.target_str)
            self.hvt_reporter.save(
                self.hvt_reporter.generate(hvt_data),
                self.module_dir / "high_value_targets.md",
            )

            # Attack path detail
            path_data = build_path_data(self.workflow, self.domain, self.target_str)
            self.attack_path_reporter.save(
                self.attack_path_reporter.generate(path_data),
                self.module_dir / "attack_paths_detail.md",
            )

            # Remediation
            rem_data = build_remediation_data(self.findings_mgr, self.domain, self.target_str)
            self.remediation_reporter.save(
                self.remediation_reporter.generate(rem_data),
                self.module_dir / "remediation.md",
            )

            # Legacy AD summary
            summary_data = build_ad_summary_data(
                results, self.domain, self.target_str, self.dc_ip, self.workflow,
            )
            self.ad_summary_reporter.save(
                self.ad_summary_reporter.generate(summary_data),
                self.module_dir / "ad_summary.md",
            )

            # Full results JSON
            (self.module_dir / "results.json").write_text(
                json.dumps(results, indent=2, default=str)
            )
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
            self.logger.info(f"Reports saved to: {self.module_dir}")
        except Exception as e:
            self.logger.error(f"Error generating reports: {e}")

    # ------------------------------------------------------------------
    # Console summary
    # ------------------------------------------------------------------

    def _print_summary(self, results: Dict) -> None:
        """Print a summary to console."""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("AD SCAN COMPLETE - Summary")
        self.logger.info(f"{'='*60}")
        self.logger.info(f"Domain: {self.domain or 'Not discovered'}")

        severity_counts = self.findings_mgr.count_by_severity()
        total = sum(severity_counts.values())
        self.logger.info(f"Total findings: {total}")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count:
                self.logger.info(f"  {sev.upper()}: {count}")

        if self.workflow.attack_paths:
            self.logger.info(f"Attack paths: {len(self.workflow.attack_paths)}")

        identity = results.get("phases", {}).get("identity", {})
        if identity:
            self.logger.info(
                f"Users: {identity.get('total_users', 0)} | "
                f"Groups: {identity.get('total_groups', 0)} | "
                f"Computers: {identity.get('total_computers', 0)}"
            )

        self.logger.info(f"Output: {self.module_dir}")
        self.logger.info(f"{'='*60}")
