"""ReconForge Web Module - Main Orchestrator

Author: Andrews Ferreira

Orchestrates the four-phase web reconnaissance kill chain:
1. Surface Discovery   - Technology fingerprinting, WAF detection, headers
2. Content Enumeration - Directory/file discovery via ffuf/gobuster
3. Vulnerability Scan  - CVE scanning via nikto/nuclei
4. Exploit Candidates  - CMS analysis (wpscan) & injection testing (sqlmap)

Usage:
    module = WebModule(target="http://10.10.10.1", output_base="outputs")
    module.run()                             # Phases 1-3 (phase 4 is opt-in)
    module.run(phases=["surface"])            # Single phase
    module.run(opsec_mode="stealth")         # Stealth mode
    module.run(phases=["exploit"], opt_in=True)  # Phase 4 explicitly
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

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
from core.profile_loader import ProfileLoader
from core.telemetry import ModuleTelemetry
from core.data_contracts import SCHEMA_VERSION, build_contract
from core.validators import validate_url

# Tool imports
from modules.web.tools.whatweb import WhatwebTool
from modules.web.tools.wafw00f import Wafw00fTool
from modules.web.tools.curl_tool import CurlTool
from modules.web.tools.nikto import NiktoTool
from modules.web.tools.gobuster import GobusterTool
from modules.web.tools.ffuf import FfufTool
from modules.web.tools.wpscan import WpscanTool
from modules.web.tools.sqlmap import SqlmapTool
from modules.web.tools.nuclei import NucleiTool

# Parser imports
from modules.web.parsers.whatweb_parser import WhatwebParser
from modules.web.parsers.wafw00f_parser import Wafw00fParser
from modules.web.parsers.nikto_parser import NiktoParser
from modules.web.parsers.gobuster_parser import GobusterParser
from modules.web.parsers.ffuf_parser import FfufParser
from modules.web.parsers.wpscan_parser import WpscanParser
from modules.web.parsers.nuclei_parser import NucleiParser

# Phase imports
from modules.web.phases.surface_discovery import SurfaceDiscoveryPhase
from modules.web.phases.content_enumeration import ContentEnumerationPhase
from modules.web.phases.vulnerability_scanning import VulnerabilityScanningPhase
from modules.web.phases.exploit_candidates import ExploitCandidatesPhase


class WebModule:
    """Main orchestrator for the Web reconnaissance module.

    Coordinates tool execution, parsing, finding generation, loot
    extraction, and attack workflow tracking across all four phases.

    Attributes:
        target_url: Target URL for web reconnaissance.
        opsec_mode: OPSEC profile (stealth, normal, aggressive).
    """

    MODULE_NAME = "web"
    VALID_PHASES = ["surface", "content", "vuln", "exploit"]

    def __init__(
        self,
        target: str,
        output_base: str = "outputs",
        opsec_mode: str = "normal",
        verbose: bool = False,
        dry_run: bool = False,
        timeout: int = 900,
        config_dir: Optional[str] = None,
        encrypt_loot: bool = False,
        scope: Optional["ScopeAuthorization"] = None,
        approval_id: Optional[str] = None,
    ) -> None:
        """Initialise the Web module.

        Args:
            target: Target URL (e.g. http://10.10.10.1 or https://example.com).
            output_base: Base directory for all outputs.
            opsec_mode: OPSEC mode (stealth, normal, aggressive).
            verbose: Enable verbose/debug logging.
            dry_run: If True, log commands without executing.
            timeout: Default timeout for commands.
            config_dir: Path to config directory.
            scope: Optional authorized-scope document (--enforce-scope);
                propagated to the Runner so every command execution is
                re-checked against it, not just the initial CLI gate.
            approval_id: Approval id to check against *scope*.
        """
        self.target_url = self._normalise_url(target)
        self.opsec_mode = opsec_mode

        self.output = OutputManager(base_dir=output_base, target=target)
        self.execution_id = f"run_{uuid.uuid4().hex[:12]}"
        # Core services
        self.logger = ReconLogger(
            name="web",
            verbose=verbose,
            log_dir=self.output.module_dir(self.MODULE_NAME),
            execution_id=self.execution_id,
        )
        self.runner = Runner(logger=self.logger, timeout=timeout, dry_run=dry_run,
                              target=target, scope=scope, approval_id=approval_id)
        self.config = ConfigLoader(config_dir=config_dir)
        self.workflow = AttackWorkflow()
        self.loot = LootManager(encrypt=encrypt_loot)
        self.findings_mgr = FindingsManager()
        self.notes = NotesManager(target=target)
        self.opsec = OpsecChecker(mode=opsec_mode, logger=self.logger)
        self.credential_vault = None  # Set by WorkflowOrchestrator
        self.telemetry = ModuleTelemetry(self.MODULE_NAME, target, execution_id=self.execution_id)

        # Output directories
        self.raw_dir = self.output.raw_dir(self.MODULE_NAME)
        self.parsed_dir = self.output.parsed_dir(self.MODULE_NAME)
        self.module_dir = self.output.module_dir(self.MODULE_NAME)

        # Profile loader — resolves OPSEC profile for timing, technique
        # toggles, and tool-specific configuration (CF-2 activation).
        self.profile = ProfileLoader(self.config, opsec_mode=opsec_mode, module=self.MODULE_NAME)

        # Initialise tools (config-aware)
        self.whatweb = WhatwebTool(self.runner, self.logger, self.raw_dir, opsec_mode,
                                  config=self.config)
        self.wafw00f = Wafw00fTool(self.runner, self.logger, self.raw_dir, opsec_mode,
                                  config=self.config)
        self.curl = CurlTool(self.runner, self.logger, self.raw_dir,
                             config=self.config)
        self.nikto = NiktoTool(self.runner, self.logger, self.raw_dir, opsec_mode,
                               config=self.config)
        self.gobuster = GobusterTool(self.runner, self.logger, self.raw_dir, opsec_mode,
                                    config=self.config)
        self.ffuf = FfufTool(self.runner, self.logger, self.raw_dir, opsec_mode,
                             config=self.config)
        self.wpscan = WpscanTool(self.runner, self.logger, self.raw_dir, opsec_mode,
                                config=self.config)
        self.sqlmap = SqlmapTool(self.runner, self.logger, self.raw_dir, opsec_mode,
                                config=self.config)
        self.nuclei = NucleiTool(self.runner, self.logger, self.raw_dir, opsec_mode,
                                config=self.config)

        # Initialise parsers
        self.whatweb_parser = WhatwebParser()
        self.wafw00f_parser = Wafw00fParser()
        self.nikto_parser = NiktoParser()
        self.gobuster_parser = GobusterParser()
        self.ffuf_parser = FfufParser()
        self.wpscan_parser = WpscanParser()
        self.nuclei_parser = NucleiParser()

        # Shared keyword args for all phases
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

        # Initialise phases
        self.phase_surface = SurfaceDiscoveryPhase(
            whatweb=self.whatweb,
            wafw00f=self.wafw00f,
            curl=self.curl,
            whatweb_parser=self.whatweb_parser,
            wafw00f_parser=self.wafw00f_parser,
            **self._phase_kwargs,
        )
        self.phase_content = ContentEnumerationPhase(
            ffuf=self.ffuf,
            gobuster=self.gobuster,
            ffuf_parser=self.ffuf_parser,
            gobuster_parser=self.gobuster_parser,
            **self._phase_kwargs,
        )
        self.phase_vuln = VulnerabilityScanningPhase(
            nikto=self.nikto,
            nuclei=self.nuclei,
            nikto_parser=self.nikto_parser,
            nuclei_parser=self.nuclei_parser,
            **self._phase_kwargs,
        )
        self.phase_exploit = ExploitCandidatesPhase(
            wpscan=self.wpscan,
            sqlmap=self.sqlmap,
            wpscan_parser=self.wpscan_parser,
            **self._phase_kwargs,
        )

    def run(
        self,
        phases: Optional[List[str]] = None,
        opt_in: bool = False,
    ) -> Dict[str, Any]:
        """Execute the web reconnaissance workflow.

        Args:
            phases: List of phases to run (surface, content, vuln, exploit).
                    None = all phases except exploit (which requires opt_in).
            opt_in: Enable Phase 4 (exploit candidates).

        Returns:
            Dict with complete scan results.
        """
        # Phase selection priority:
        # 1. Explicit phases argument
        # 2. Profile-driven enabled_phases()
        # 3. Default: surface, content, vuln (exploit requires opt_in)
        if phases:
            phases_to_run = phases
        else:
            profile_phases = self.profile.enabled_phases()
            phases_to_run = profile_phases if profile_phases else ["surface", "content", "vuln"]

        # Credential vault: ingest available credentials at start
        if self.credential_vault:
            imported = self.credential_vault.ingest_from_loot(self.loot)
            if imported:
                self.logger.info(f"Imported {imported} credentials from vault")

        # If exploit explicitly requested, ensure opt_in is True
        if "exploit" in phases_to_run:
            opt_in = True

        self.logger.info(f"{'='*60}")
        self.logger.info(f"ReconForge Web Module - Target: {self.target_url}")
        self.logger.info(f"OPSEC Mode: {self.opsec_mode} | Profile: {self.profile.opsec_mode} | Phases: {', '.join(phases_to_run)}")
        self.logger.info(f"Output: {self.module_dir}")
        self.logger.info(f"{'='*60}")

        self.notes.add(f"Web module started against {self.target_url}", "phase")
        self.notes.add(
            f"OPSEC mode: {self.opsec_mode}, Phases: {', '.join(phases_to_run)}, "
            f"Opt-in exploits: {opt_in}",
            "general",
        )

        # Check tool availability
        self._check_tools()

        results: Dict[str, Any] = {
            "target": self.target_url,
            "opsec_mode": self.opsec_mode,
            "schema_version": SCHEMA_VERSION,
            "execution_id": self.execution_id,
            "start_time": datetime.now().isoformat(),
            "phases": {},
        }

        try:
            # Phase 1: Surface Discovery
            if "surface" in phases_to_run:
                surface_results = self.telemetry.run_phase(
                    "surface",
                    lambda: self.phase_surface.execute(
                        target_url=self.target_url,
                    ),
                )
                results["phases"]["surface"] = surface_results
            else:
                surface_results = {}

            # Phase 2: Content Enumeration
            if "content" in phases_to_run:
                waf_info = surface_results.get("waf") or {}
                waf_detected = bool(waf_info.get("detected", False))
                content_results = self.telemetry.run_phase(
                    "content",
                    lambda: self.phase_content.execute(
                        target_url=self.target_url,
                        waf_detected=waf_detected,
                    ),
                )
                results["phases"]["content"] = content_results

            # Phase 3: Vulnerability Scanning
            if "vuln" in phases_to_run:
                vuln_results = self.telemetry.run_phase(
                    "vuln",
                    lambda: self.phase_vuln.execute(
                        target_url=self.target_url,
                    ),
                )
                results["phases"]["vuln"] = vuln_results

            # Phase 4: Exploit Candidates (opt-in)
            if "exploit" in phases_to_run:
                technologies = surface_results.get("technologies", [])
                exploit_results = self.telemetry.run_phase(
                    "exploit",
                    lambda: self.phase_exploit.execute(
                        target_url=self.target_url,
                        opt_in=opt_in,
                        technologies=technologies,
                    ),
                )
                results["phases"]["exploit"] = exploit_results

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

        results["success"] = "error" not in results

        # Credential vault: contribute discovered credentials at end
        if self.credential_vault:
            contributed = self.credential_vault.ingest_from_loot(self.loot)
            if contributed:
                self.logger.info(f"Contributed {contributed} credentials to vault")

        self._print_summary(results)
        return results

    # ── Internal helpers ───────────────────────────────────────────

    @staticmethod
    def _normalise_url(target: str) -> str:
        """Ensure target has a URL scheme and passes URL validation."""
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        target = target.rstrip("/")
        return validate_url(target)

    def _check_tools(self) -> Dict[str, bool]:
        """Check availability of web reconnaissance tools."""
        tools = {
            "whatweb": self.whatweb.is_available(),
            "wafw00f": self.wafw00f.is_available(),
            "curl": self.curl.is_available(),
            "nikto": self.nikto.is_available(),
            "gobuster": self.gobuster.is_available(),
            "ffuf": self.ffuf.is_available(),
            "wpscan": self.wpscan.is_available(),
            "sqlmap": self.sqlmap.is_available(),
            "nuclei": self.nuclei.is_available(),
        }

        available = [t for t, a in tools.items() if a]
        missing = [t for t, a in tools.items() if not a]

        for tool in available:
            self.logger.debug(f"Tool available: {tool}")
        for tool in missing:
            self.logger.warning(f"Tool not found: {tool} (some features will be skipped)")

        self.notes.add(
            f"Tool check: {', '.join(available) or 'none'} available; "
            f"{', '.join(missing) or 'none'} missing",
            "general",
        )

        return tools

    def _generate_reports(self, results: Dict) -> None:
        """Generate all output reports."""
        self.logger.info("Generating reports...")

        try:
            # findings.json
            self.findings_mgr.save_json(
                self.output.findings_file(self.MODULE_NAME, "json")
            )
            self.findings_mgr.save_contract(
                self.output.contract_file(self.MODULE_NAME, "findings"),
                execution_id=self.execution_id,
                module=self.MODULE_NAME,
            )

            # findings.md
            self.findings_mgr.save_markdown(
                self.output.findings_file(self.MODULE_NAME, "md")
            )

            # session.md
            self.notes.save(self.output.session_file(self.MODULE_NAME))

            # attack_paths.md
            attack_paths_content = self.workflow.to_markdown()
            self.output.attack_paths_file(self.MODULE_NAME).write_text(
                attack_paths_content
            )

            # commands.log
            self.runner.save_command_log(
                self.output.commands_log(self.MODULE_NAME)
            )

            # loot.json (CF-3: always use LootManager API via OutputManager)
            self.loot.save(self.output.loot_file(self.MODULE_NAME))
            self.loot.save_contract(
                self.output.contract_file(self.MODULE_NAME, "loot"),
                execution_id=self.execution_id,
                module=self.MODULE_NAME,
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

            # quick_report.md
            self._generate_quick_report(results)

            self.logger.info(f"Reports saved to: {self.module_dir}")

        except Exception as e:
            self.logger.error(f"Error generating reports: {e}")

    def _generate_quick_report(self, results: Dict) -> None:
        """Generate executive summary report."""
        report_path = self.output.report_file(self.MODULE_NAME)

        severity_counts = self.findings_mgr.count_by_severity()
        loot_summary = self.loot.summary()
        total_findings = sum(severity_counts.values())

        lines = [
            "# ReconForge Quick Report - Web Module\n",
            f"**Target:** {self.target_url}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**OPSEC Mode:** {self.opsec_mode}",
            f"**Author:** Andrews Ferreira",
            "",
            "## Executive Summary\n",
            f"Web reconnaissance of **{self.target_url}** identified "
            f"**{total_findings}** findings:\n",
        ]

        vuln_phase = results.get("phases", {}).get("vuln", {})
        risk_score = vuln_phase.get("risk_score")
        severity_summary = vuln_phase.get("severity_summary", {})
        if isinstance(risk_score, int):
            lines.append(f"- **Web Risk Score (phase vuln):** {risk_score}/100")
        if severity_summary:
            lines.append(
                "- **Vuln Severity Mix:** "
                + ", ".join(f"{k}={v}" for k, v in severity_summary.items() if v > 0)
            )

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            icon = {
                "critical": "🔴", "high": "🟠", "medium": "🟡",
                "low": "🔵", "info": "⚪",
            }.get(sev, "⚪")
            lines.append(f"- {icon} **{sev.upper()}:** {count}")

        if self.findings_mgr.clamped_count:
            lines.append(
                f"\n⚠️ **{self.findings_mgr.clamped_count} finding(s) had severity downgraded "
                "due to weak confidence** — they may not appear in the Critical & High "
                "Findings section below even though they started at a higher severity. "
                "See `findings.md` for the full, unfiltered list."
            )

        lines.append("")
        lines.append("## Loot Summary\n")
        if loot_summary:
            for ltype, count in loot_summary.items():
                lines.append(f"- **{ltype}:** {count} item(s)")
        else:
            lines.append("- No loot collected.")

        # Critical and high findings detail
        critical_high = (
            self.findings_mgr.get_by_severity("critical")
            + self.findings_mgr.get_by_severity("high")
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

        # Suggested next steps
        suggestions = self.workflow.get_suggestions()
        if suggestions:
            lines.append("## Suggested Next Steps\n")
            for s in suggestions[:10]:
                lines.append(f"- [{s['priority'].upper()}] `{s['command']}`")
                lines.append(f"  - {s['justification']}")

        lines.append(
            f"\n---\n*Generated by ReconForge v1.0 release on "
            f"{datetime.now():%Y-%m-%d %H:%M:%S}*\n"
        )

        report_path.write_text("\n".join(lines))

    def _print_summary(self, results: Dict) -> None:
        """Print a summary to console."""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("WEB SCAN COMPLETE - Summary")
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
