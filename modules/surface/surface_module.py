"""ReconForge Surface Module - Main Orchestrator

Author: Andrews Ferreira

Orchestrates the four-phase attack-surface reconnaissance kill chain:
1. Port Discovery        - Stealth port scanning to map exposed services
2. Service Fingerprint   - Version detection and HTTP probing
3. Vector Correlation    - Map services to known attack vectors
4. Prioritisation        - Score and rank the attack surface

Usage:
    module = SurfaceModule(target="10.10.10.1", output_base="outputs")
    module.run()                                    # All phases
    module.run(phases=["port_discovery"])            # Single phase
    module.run(opsec_mode="stealth")                # Stealth mode
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

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
from core.target_parser import parse_target

# Tool imports
from modules.surface.tools.nmap_stealth import NmapStealthTool
from modules.surface.tools.service_detector import ServiceDetectorTool

# Parser imports
from modules.surface.parsers.surface_parser import SurfaceParser

# Phase imports
from modules.surface.phases.port_discovery import PortDiscoveryPhase
from modules.surface.phases.service_fingerprint import ServiceFingerprintPhase
from modules.surface.phases.vector_correlation import VectorCorrelationPhase
from modules.surface.phases.prioritization import PrioritizationPhase


class SurfaceModule:
    """Main orchestrator for the attack-surface reconnaissance module.

    Coordinates tool execution, parsing, finding generation, loot
    extraction, and attack workflow tracking across all four phases.

    Attributes:
        target: Parsed target object.
        opsec_mode: OPSEC profile (stealth, normal, aggressive).
    """

    MODULE_NAME = "surface"
    VALID_PHASES = ["port_discovery", "service_fingerprint",
                    "vector_correlation", "prioritization"]

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
    ) -> None:
        """Initialise the Surface module.

        Args:
            target: Target IP / hostname / CIDR.
            output_base: Base directory for all outputs.
            opsec_mode: OPSEC mode (stealth, normal, aggressive).
            verbose: Enable verbose/debug logging.
            dry_run: If True, log commands without executing.
            timeout: Default timeout for commands.
            config_dir: Path to config directory.
            encrypt_loot: Encrypt loot files with Fernet.
        """
        self.target = parse_target(target)
        self.opsec_mode = opsec_mode

        # Core services
        self.logger = ReconLogger(name="surface", verbose=verbose)
        self.runner = Runner(logger=self.logger, timeout=timeout, dry_run=dry_run)
        self.config = ConfigLoader(config_dir=config_dir)
        self.output = OutputManager(base_dir=output_base, target=target)
        self.workflow = AttackWorkflow()
        self.loot = LootManager(encrypt=encrypt_loot)
        self.findings_mgr = FindingsManager()
        self.notes = NotesManager(target=target)
        self.opsec = OpsecChecker(mode=opsec_mode, logger=self.logger)
        self.credential_vault = None  # Set by WorkflowOrchestrator
        self.profile = ProfileLoader(
            config=self.config, opsec_mode=opsec_mode, module=self.MODULE_NAME
        )

        # Output directories
        self.raw_dir = self.output.raw_dir(self.MODULE_NAME)
        self.parsed_dir = self.output.parsed_dir(self.MODULE_NAME)
        self.module_dir = self.output.module_dir(self.MODULE_NAME)

        # Initialise tools (profile-aware, config-aware)
        self.nmap = NmapStealthTool(
            self.runner, self.logger, self.raw_dir, opsec_mode,
            profile=self.profile, config=self.config,
        )
        self.detector = ServiceDetectorTool(
            self.runner, self.logger, self.raw_dir, opsec_mode,
            config=self.config,
        )

        # Initialise parsers
        self.surface_parser = SurfaceParser()

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
        self.phase_port_discovery = PortDiscoveryPhase(
            nmap=self.nmap,
            parser=self.surface_parser,
            **self._phase_kwargs,
        )
        self.phase_service_fingerprint = ServiceFingerprintPhase(
            nmap=self.nmap,
            detector=self.detector,
            parser=self.surface_parser,
            **self._phase_kwargs,
        )
        self.phase_vector_correlation = VectorCorrelationPhase(
            **self._phase_kwargs,
        )
        self.phase_prioritization = PrioritizationPhase(
            **self._phase_kwargs,
        )

    def run(
        self,
        phases: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Execute the attack-surface reconnaissance workflow.

        Args:
            phases: List of phases to run. None = all four phases.

        Returns:
            Dict with complete scan results.
        """
        # Phase selection priority:
        # 1. Explicit phases argument
        # 2. Profile-driven enabled_phases()
        # 3. All VALID_PHASES (default)
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

        self.logger.info(f"{'='*60}")
        self.logger.info(f"ReconForge Surface Module - Target: {self.target}")
        self.logger.info(
            f"OPSEC Mode: {self.opsec_mode} | Profile: {self.profile.opsec_mode} | Phases: {', '.join(phases_to_run)}"
        )
        self.logger.info(f"Output: {self.module_dir}")
        self.logger.info(f"{'='*60}")

        self.notes.add(f"Surface module started against {self.target}", "phase")
        self.notes.add(
            f"OPSEC mode: {self.opsec_mode}, Phases: {', '.join(phases_to_run)}",
            "general",
        )

        # Check tool availability
        self._check_tools()

        results: Dict[str, Any] = {
            "target": str(self.target),
            "opsec_mode": self.opsec_mode,
            "start_time": datetime.now().isoformat(),
            "phases": {},
        }

        try:
            # Phase 1: Port Discovery
            if "port_discovery" in phases_to_run:
                discovery_results = self.phase_port_discovery.execute(
                    target=str(self.target),
                )
                results["phases"]["port_discovery"] = discovery_results
            else:
                discovery_results = {}

            ports = discovery_results.get("ports", [])

            # Phase 2: Service Fingerprint
            if "service_fingerprint" in phases_to_run:
                fp_results = self.phase_service_fingerprint.execute(
                    target=str(self.target),
                    ports=ports,
                )
                results["phases"]["service_fingerprint"] = fp_results
            else:
                fp_results = {}

            services = fp_results.get("services", [])
            http_services = fp_results.get("http_services", [])

            # Phase 3: Vector Correlation
            if "vector_correlation" in phases_to_run:
                corr_results = self.phase_vector_correlation.execute(
                    target=str(self.target),
                    ports=ports,
                    services=services,
                    http_services=http_services,
                )
                results["phases"]["vector_correlation"] = corr_results
            else:
                corr_results = {}

            vectors = corr_results.get("vectors", [])
            surface_map = corr_results.get("surface_map", {})
            confidence_scores = corr_results.get("confidence_scores", {})

            # Phase 4: Prioritisation
            if "prioritization" in phases_to_run:
                prio_results = self.phase_prioritization.execute(
                    target=str(self.target),
                    vectors=vectors,
                    ports=ports,
                    http_services=http_services,
                    surface_map=surface_map,
                    confidence_scores=confidence_scores,
                )
                results["phases"]["prioritization"] = prio_results

        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            results["interrupted"] = True
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            results["error"] = str(e)
            raise
        finally:
            results["end_time"] = datetime.now().isoformat()
            self._generate_reports(results)

        results["success"] = "error" not in results

        # Credential vault: contribute discovered credentials at end
        if self.credential_vault:
            contributed = self.credential_vault.ingest_from_loot(self.loot)
            if contributed:
                self.logger.info(f"Contributed {contributed} credentials to vault")

        self._print_summary(results)
        return results

    # \u2500\u2500 Internal helpers \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    def _check_tools(self) -> Dict[str, bool]:
        """Check availability of surface reconnaissance tools."""
        tools = {
            "nmap": self.nmap.is_available(),
            "httpx": self.detector.is_available(),
        }

        available = [t for t, a in tools.items() if a]
        missing = [t for t, a in tools.items() if not a]

        for tool in available:
            self.logger.debug(f"Tool available: {tool}")
        for tool in missing:
            self.logger.warning(
                f"Tool not found: {tool} (some features will be skipped)"
            )

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

            # loot.json
            self.loot.save(self.output.loot_file(self.MODULE_NAME))

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
            "# ReconForge Quick Report - Surface Module\n",
            f"**Target:** {self.target}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**OPSEC Mode:** {self.opsec_mode}",
            f"**Author:** Andrews Ferreira",
            "",
            "## Executive Summary\n",
            f"Attack-surface reconnaissance of **{self.target}** identified "
            f"**{total_findings}** findings:\n",
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            icon = {
                "critical": "\U0001f534", "high": "\U0001f7e0",
                "medium": "\U0001f7e1", "low": "\U0001f535", "info": "\u26aa",
            }.get(sev, "\u26aa")
            lines.append(f"- {icon} **{sev.upper()}:** {count}")

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

        # Prioritization summary (from intelligent prioritizer)
        prio_phase = results.get("phases", {}).get("prioritization", {})
        quick_wins = prio_phase.get("quick_wins", [])
        if quick_wins:
            lines.append("## Quick Wins (Start Here)\n")
            for qw in quick_wins[:5]:
                lines.append(
                    f"- **{qw.get('display_name', 'Unknown')}** "
                    f"(ports: {', '.join(str(p) for p in qw.get('ports', []))})"
                )
                flags = qw.get("flags", [])
                if flags:
                    lines.append(f"  - Flags: {', '.join(flags)}")
                next_steps = qw.get("next_steps", [])
                if next_steps:
                    lines.append(f"  - Start: {next_steps[0]}")
            lines.append("")

        exec_summary = prio_phase.get("executive_summary", "")
        if exec_summary:
            lines.append("## Intelligence Summary\n")
            lines.append(exec_summary)
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
        self.logger.info("SURFACE SCAN COMPLETE - Summary")
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