"""ReconForge API Module - Main Orchestrator

Author: Andrews Ferreira

Orchestrates the four-phase API reconnaissance kill chain:
1. Discovery       - API endpoint enumeration, spec detection, technology probing
2. Authentication  - Auth mechanism analysis, JWT testing, credential checks
3. Fuzzing         - Parameter discovery, input fuzzing, injection testing
4. Authorization   - BOLA/IDOR detection, privilege escalation, access control

Usage:
    module = APIModule(target="http://10.10.10.1/api", output_base="outputs")
    module.run()                                  # Phases 1-3 (phase 4 is opt-in)
    module.run(phases=["discovery"])               # Single phase
    module.run(opsec_mode="stealth")              # Stealth mode
    module.run(phases=["authorization"], opt_in=True)  # Phase 4 explicitly
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
from core.version import __version__

# Tool imports
from modules.api.tools.ffuf_api import FfufApiTool
from modules.api.tools.arjun_tool import ArjunTool
from modules.api.tools.nuclei_api import NucleiApiTool
from modules.api.tools.httpx_tool import HttpxTool

# Parser imports
from modules.api.parsers.ffuf_parser import FfufApiParser
from modules.api.parsers.arjun_parser import ArjunParser
from modules.api.parsers.nuclei_parser import NucleiApiParser
from modules.api.parsers.openapi_parser import OpenApiParser

# Phase imports
from modules.api.phases.discovery import DiscoveryPhase
from modules.api.phases.authentication import AuthenticationPhase
from modules.api.phases.fuzzing import FuzzingPhase
from modules.api.phases.authorization import AuthorizationPhase


class APIModule:
    """Main orchestrator for the API reconnaissance module.

    Coordinates tool execution, parsing, finding generation, loot
    extraction, and attack workflow tracking across all four phases.

    Attributes:
        target_url: Target API base URL.
        opsec_mode: OPSEC profile (stealth, normal, aggressive).
    """

    MODULE_NAME = "api"
    VALID_PHASES = ["discovery", "authentication", "fuzzing", "authorization"]

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
        headers: Optional[List[str]] = None,
        auth_token: Optional[str] = None,
        scope: Optional["ScopeAuthorization"] = None,
        approval_id: Optional[str] = None,
    ) -> None:
        """Initialise the API module.

        Args:
            target: Target API base URL (e.g. http://10.10.10.1/api/v1).
            output_base: Base directory for all outputs.
            opsec_mode: OPSEC mode (stealth, normal, aggressive).
            verbose: Enable verbose/debug logging.
            dry_run: If True, log commands without executing.
            timeout: Default timeout for commands.
            config_dir: Path to config directory.
            encrypt_loot: Encrypt loot files with Fernet.
            headers: Extra HTTP headers (e.g. ["X-Api-Key: abc"]).
            auth_token: Bearer token for authenticated requests.
            scope: Optional authorized-scope document (--enforce-scope);
                propagated to the Runner so every command execution is
                re-checked against it, not just the initial CLI gate.
            approval_id: Approval id to check against *scope*.
        """
        self.target_url = self._normalise_url(target)
        self.opsec_mode = opsec_mode
        self.headers = headers or []
        self.auth_token = auth_token

        self.output = OutputManager(base_dir=output_base, target=target)
        self.execution_id = f"run_{uuid.uuid4().hex[:12]}"
        # Core services
        self.logger = ReconLogger(
            name="api",
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

        # Profile loader — resolves OPSEC profile for timing, technique
        # toggles, and tool-specific configuration (CF-2 activation).
        self.profile = ProfileLoader(config=self.config, opsec_mode=opsec_mode, module=self.MODULE_NAME)

        # Output directories
        self.raw_dir = self.output.raw_dir(self.MODULE_NAME)
        self.parsed_dir = self.output.parsed_dir(self.MODULE_NAME)
        self.module_dir = self.output.module_dir(self.MODULE_NAME)

        # Initialise tools
        self.ffuf = FfufApiTool(self.runner, self.logger, self.raw_dir, opsec_mode,
                               config=self.config)
        self.arjun = ArjunTool(self.runner, self.logger, self.raw_dir, opsec_mode,
                               config=self.config)
        self.nuclei = NucleiApiTool(self.runner, self.logger, self.raw_dir, opsec_mode,
                                   config=self.config)
        self.httpx = HttpxTool(self.runner, self.logger, self.raw_dir, opsec_mode,
                               config=self.config)

        # Initialise parsers
        self.ffuf_parser = FfufApiParser()
        self.arjun_parser = ArjunParser()
        self.nuclei_parser = NucleiApiParser()
        self.openapi_parser = OpenApiParser()

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
        self.phase_discovery = DiscoveryPhase(
            httpx=self.httpx,
            ffuf=self.ffuf,
            ffuf_parser=self.ffuf_parser,
            openapi_parser=self.openapi_parser,
            **self._phase_kwargs,
        )
        self.phase_authentication = AuthenticationPhase(
            httpx=self.httpx,
            nuclei=self.nuclei,
            nuclei_parser=self.nuclei_parser,
            openapi_parser=self.openapi_parser,
            **self._phase_kwargs,
        )
        self.phase_fuzzing = FuzzingPhase(
            arjun=self.arjun,
            ffuf=self.ffuf,
            arjun_parser=self.arjun_parser,
            ffuf_parser=self.ffuf_parser,
            **self._phase_kwargs,
        )
        self.phase_authorization = AuthorizationPhase(
            nuclei=self.nuclei,
            httpx=self.httpx,
            nuclei_parser=self.nuclei_parser,
            **self._phase_kwargs,
        )

    def run(
        self,
        phases: Optional[List[str]] = None,
        opt_in: bool = False,
    ) -> Dict[str, Any]:
        """Execute the API reconnaissance workflow.

        Args:
            phases: List of phases to run (discovery, authentication, fuzzing, authorization).
                    None = all phases except authorization (which requires opt_in).
            opt_in: Enable Phase 4 (authorization testing).

        Returns:
            Dict with complete scan results.
        """
        # Phase selection priority:
        # 1. Explicit phases argument
        # 2. Profile-driven enabled_phases()
        # 3. Default: discovery, authentication, fuzzing
        if phases:
            phases_to_run = phases
        else:
            profile_phases = self.profile.enabled_phases()
            phases_to_run = profile_phases if profile_phases else ["discovery", "authentication", "fuzzing"]

        # Credential vault: ingest available credentials at start
        if self.credential_vault:
            imported = self.credential_vault.ingest_from_loot(self.loot)
            if imported:
                self.logger.info(f"Imported {imported} credentials from vault")

        # If authorization explicitly requested, ensure opt_in is True
        if "authorization" in phases_to_run:
            opt_in = True

        self.logger.info(f"{'='*60}")
        self.logger.info(f"ReconForge API Module - Target: {self.target_url}")
        self.logger.info(f"OPSEC Mode: {self.opsec_mode} | Profile: {self.profile.opsec_mode} | Phases: {', '.join(phases_to_run)}")
        self.logger.info(f"Output: {self.module_dir}")
        self.logger.info(f"{'='*60}")

        self.notes.add(f"API module started against {self.target_url}", "phase")
        self.notes.add(
            f"OPSEC mode: {self.opsec_mode}, Phases: {', '.join(phases_to_run)}, "
            f"Opt-in authz: {opt_in}",
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
            # Phase 1: Discovery
            if "discovery" in phases_to_run:
                discovery_results = self.telemetry.run_phase(
                    "discovery",
                    lambda: self.phase_discovery.execute(
                        target_url=self.target_url,
                        headers=self.headers,
                        auth_token=self.auth_token,
                    ),
                )
                results["phases"]["discovery"] = discovery_results
            else:
                discovery_results = {}

            # Phase 2: Authentication
            if "authentication" in phases_to_run:
                endpoints = discovery_results.get("endpoints", [])
                spec_data = discovery_results.get("spec_data")  # Enhanced OpenApiSpec
                auth_results = self.telemetry.run_phase(
                    "authentication",
                    lambda: self.phase_authentication.execute(
                        target_url=self.target_url,
                        endpoints=endpoints,
                        spec_data=spec_data,
                        headers=self.headers,
                        auth_token=self.auth_token,
                    ),
                )
                results["phases"]["authentication"] = auth_results

            # Phase 3: Fuzzing
            if "fuzzing" in phases_to_run:
                endpoints = discovery_results.get("endpoints", [])
                fuzz_results = self.telemetry.run_phase(
                    "fuzzing",
                    lambda: self.phase_fuzzing.execute(
                        target_url=self.target_url,
                        endpoints=endpoints,
                        headers=self.headers,
                        auth_token=self.auth_token,
                    ),
                )
                results["phases"]["fuzzing"] = fuzz_results

            # Phase 4: Authorization (opt-in)
            if "authorization" in phases_to_run:
                endpoints = discovery_results.get("endpoints", [])
                discovered_params = []
                if "fuzzing" in results.get("phases", {}):
                    discovered_params = results["phases"]["fuzzing"].get(
                        "discovered_params", []
                    )
                spec_data = discovery_results.get("spec_data")
                authz_results = self.telemetry.run_phase(
                    "authorization",
                    lambda: self.phase_authorization.execute(
                        target_url=self.target_url,
                        endpoints=endpoints,
                        discovered_params=discovered_params,
                        spec_data=spec_data,
                        opt_in=opt_in,
                        headers=self.headers,
                        auth_token=self.auth_token,
                    ),
                )
                results["phases"]["authorization"] = authz_results

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

    # ── Internal helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _normalise_url(target: str) -> str:
        """Ensure target has a URL scheme and passes URL validation."""
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        target = target.rstrip("/")
        return validate_url(target)

    def _check_tools(self) -> Dict[str, bool]:
        """Check availability of API reconnaissance tools."""
        tools = {
            "ffuf": self.ffuf.is_available(),
            "arjun": self.arjun.is_available(),
            "nuclei": self.nuclei.is_available(),
            "httpx": self.httpx.is_available(),
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

            # loot.json
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
            # quick_report.md
            self._generate_quick_report(results)

            # evidence.manifest.json — must be written last: it hashes
            # every file already in the module directory, so any artifact
            # written after it (previously quick_report.md) would be
            # silently excluded from the integrity chain.
            self.output.write_evidence_manifest(self.MODULE_NAME, self.execution_id)

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
            "# ReconForge Quick Report - API Module\n",
            f"**Target:** {self.target_url}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**OPSEC Mode:** {self.opsec_mode}",
            f"**Author:** Andrews Ferreira",
            "",
            "## Executive Summary\n",
            f"API reconnaissance of **{self.target_url}** identified "
            f"**{total_findings}** findings:\n",
        ]

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
            f"\n---\n*Generated by ReconForge v{__version__} on "
            f"{datetime.now():%Y-%m-%d %H:%M:%S}*\n"
        )

        report_path.write_text("\n".join(lines))

    def _print_summary(self, results: Dict) -> None:
        """Print a summary to console."""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("API SCAN COMPLETE - Summary")
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
