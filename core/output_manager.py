"""ReconForge Output Manager - Structured output directory management."""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # avoid circular imports at runtime
    from core.findings_manager import FindingsManager
    from core.loot_manager import LootManager
    from core.attack_workflow import AttackWorkflow
    from core.reporting.models import ReportingBundle


class OutputManager:
    """Manage output directory structure for a target."""

    def __init__(self, base_dir: str = "outputs", target: str = "default"):
        self.base = Path(base_dir) / self._sanitize(target)
        self.target = target

    @staticmethod
    def _sanitize(name: str) -> str:
        """Sanitize target name for directory use."""
        return name.replace("/", "_").replace(":", "_").replace(" ", "_")

    # ── Directory helpers ───────────────────────────────────────────

    def module_dir(self, module: str) -> Path:
        """Get the base directory for a module."""
        d = self.base / module
        d.mkdir(parents=True, exist_ok=True)
        return d

    def raw_dir(self, module: str) -> Path:
        """Get the raw output directory for a module."""
        d = self.base / module / "raw"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def parsed_dir(self, module: str) -> Path:
        """Get the parsed output directory for a module."""
        d = self.base / module / "parsed"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def findings_file(self, module: str, ext: str = "json") -> Path:
        """Get path for findings file."""
        d = self.module_dir(module)
        return d / f"findings.{ext}"

    def session_file(self, module: str) -> Path:
        """Get path for session notes."""
        return self.module_dir(module) / "session.md"

    def commands_log(self, module: str) -> Path:
        """Get path for commands log."""
        return self.module_dir(module) / "commands.log"

    def attack_paths_file(self, module: str) -> Path:
        """Get path for attack paths documentation."""
        return self.module_dir(module) / "attack_paths.md"

    def report_file(self, module: str) -> Path:
        """Get path for quick report."""
        return self.module_dir(module) / "quick_report.md"

    def loot_file(self, module: str) -> Path:
        """Get path for loot file."""
        return self.module_dir(module) / "loot.json"

    def contract_file(self, module: str, kind: str) -> Path:
        """Get path for versioned contract sidecar file."""
        return self.module_dir(module) / f"{kind}.contract.json"

    def audit_file(self, module: str) -> Path:
        """Get path for module execution audit metadata."""
        return self.module_dir(module) / "audit.json"

    def evidence_manifest_file(self, module: str) -> Path:
        """Get path for evidence chain manifest."""
        return self.module_dir(module) / "evidence.manifest.json"

    def reporting_root(self) -> Path:
        """Get root directory for phase-5 reporting artifacts."""
        root = self.base / "reporting"
        root.mkdir(parents=True, exist_ok=True)
        return root

    def reporting_layer_dir(self, layer: str) -> Path:
        """Get a specific reporting layer directory.

        Valid layers:
        - raw
        - normalized
        - correlated
        - reports
        - manifests
        - structured
        """
        allowed = {"raw", "normalized", "correlated", "reports", "manifests", "structured"}
        if layer not in allowed:
            raise ValueError(f"Unsupported reporting layer: {layer}")
        d = self.reporting_root() / layer
        d.mkdir(parents=True, exist_ok=True)
        return d

    def write_evidence_manifest(self, module: str, execution_id: str) -> Path:
        """Write a chained-hash manifest for all module artifacts.

        The chain is deterministic (sorted by relative path). Each entry includes
        its file hash and a `chain_hash` bound to previous entry hash.
        """
        root = self.module_dir(module)
        manifest_path = self.evidence_manifest_file(module)
        entries: List[Dict[str, str]] = []
        previous_chain_hash = ""

        for file_path in sorted(p for p in root.rglob("*") if p.is_file()):
            if file_path == manifest_path:
                continue
            rel = file_path.relative_to(root).as_posix()
            digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
            chain_hash = hashlib.sha256(
                f"{previous_chain_hash}:{rel}:{digest}".encode("utf-8")
            ).hexdigest()
            entries.append(
                {
                    "path": rel,
                    "sha256": digest,
                    "chain_hash": chain_hash,
                }
            )
            previous_chain_hash = chain_hash

        payload: Dict[str, Any] = {
            "version": "1.0",
            "execution_id": execution_id,
            "module": module,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "entries": entries,
            "root_chain_hash": previous_chain_hash,
        }
        manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return manifest_path

    def generate_reporting_bundle(self, bundle: "ReportingBundle") -> Dict[str, Path]:
        """Generate phase-5 reporting artifacts under deterministic directories."""
        from core.reporting.pipeline import ReportingPipeline

        pipeline = ReportingPipeline()
        return pipeline.generate(bundle, self.base)

    # ── Unified engagement report (IF-2) ────────────────────────────

    def generate_engagement_report(
        self,
        findings: "FindingsManager",
        loot: "LootManager",
        workflow: "AttackWorkflow",
        modules_run: Optional[List[str]] = None,
        opsec_mode: str = "normal",
        html: bool = False,
    ) -> Path:
        """Generate a unified engagement report aggregating all modules.

        Args:
            findings: Populated FindingsManager with data from all modules.
            loot: Populated LootManager with aggregated loot.
            workflow: AttackWorkflow with steps and attack paths.
            modules_run: List of module names that were executed.
            opsec_mode: OPSEC mode used during the engagement.
            html: If True, also generate an HTML version.

        Returns:
            Path to the generated Markdown report.
        """
        modules_run = modules_run or []
        now = datetime.now()
        md_path = self.base / "engagement_report.md"
        self.base.mkdir(parents=True, exist_ok=True)

        severity_counts = findings.count_by_severity()
        total_findings = sum(severity_counts.values())
        loot_summary = loot.summary()
        total_loot = sum(loot_summary.values())

        lines: List[str] = []

        # ── Title & meta ────────────────────────────────────────────
        lines.append("# ReconForge Engagement Report\n")
        lines.append(f"**Target:** {self.target}  ")
        lines.append(f"**Date:** {now:%Y-%m-%d %H:%M:%S}  ")
        lines.append(f"**OPSEC Mode:** {opsec_mode}  ")
        lines.append(f"**Modules:** {', '.join(modules_run) or 'N/A'}  ")
        lines.append(f"**Author:** ReconForge v1.0\n")

        # ── Executive Summary ───────────────────────────────────────
        lines.append("## Executive Summary\n")
        lines.append(
            f"Reconnaissance of **{self.target}** identified "
            f"**{total_findings}** findings and **{total_loot}** loot items "
            f"across {len(modules_run)} module(s).\n"
        )

        # Severity breakdown
        lines.append("### Findings by Severity\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        icon_map = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(sev, 0)
            lines.append(f"| {icon_map.get(sev, '')} {sev.upper()} | {count} |")
        lines.append("")

        # Loot summary
        if loot_summary:
            lines.append("### Loot Summary\n")
            lines.append("| Type | Count |")
            lines.append("|------|-------|")
            for ltype, count in sorted(loot_summary.items()):
                lines.append(f"| {ltype} | {count} |")
            lines.append("")

        # ── Findings detail ─────────────────────────────────────────
        all_findings = findings.get_all()
        if all_findings:
            lines.append("## Detailed Findings\n")
            for f in all_findings:
                icon = icon_map.get(f.severity, "⚪")
                lines.append(f"### {icon} [{f.severity.upper()}] {f.description}\n")
                lines.append(f"- **ID:** {f.id}")
                lines.append(f"- **Type:** {f.finding_type}")
                lines.append(f"- **Target:** {f.target}")
                lines.append(f"- **Module / Phase:** {f.module} / {f.phase}")
                lines.append(f"- **Confidence:** {f.confidence}")
                if f.evidence:
                    lines.append(f"- **Evidence:**\n```\n{f.evidence}\n```")
                if f.recommendation:
                    lines.append(f"- **Recommendation:** {f.recommendation}")
                if f.references:
                    lines.append("- **References:**")
                    for ref in f.references:
                        lines.append(f"  - {ref}")
                lines.append("")

        # ── Attack Paths ────────────────────────────────────────────
        if workflow.attack_paths:
            lines.append("## Attack Paths\n")
            for ap in workflow.attack_paths:
                lines.append(f"### {ap.name} [{ap.risk.upper()}]\n")
                lines.append(f"{ap.description}\n")
                if ap.tactic:
                    lines.append(f"- **Tactic:** {ap.tactic}")
                if ap.technique_id:
                    lines.append(f"- **Technique:** {ap.technique_id}")
                lines.append("**Steps:**")
                for i, step in enumerate(ap.steps, 1):
                    lines.append(f"{i}. {step}")
                if ap.prerequisites:
                    lines.append(f"\n**Prerequisites:** {', '.join(ap.prerequisites)}")
                lines.append("")

        # ── Timeline ────────────────────────────────────────────────
        if workflow.steps:
            lines.append("## Activity Timeline\n")
            lines.append("| Time | Phase | Hypothesis | Result |")
            lines.append("|------|-------|------------|--------|")
            for s in workflow.steps:
                lines.append(f"| {s.timestamp} | {s.phase} | {s.hypothesis} | {s.result or '—'} |")
            lines.append("")

        # ── Suggested Next Steps ────────────────────────────────────
        suggestions = workflow.get_suggestions()
        if suggestions:
            lines.append("## Suggested Next Steps\n")
            for s in suggestions[:15]:
                lines.append(f"- [{s['priority'].upper()}] `{s['command']}`")
                lines.append(f"  - {s['justification']}")
            lines.append("")

        # Footer
        lines.append(f"\n---\n*Generated by ReconForge v1.0 release on {now:%Y-%m-%d %H:%M:%S}*\n")

        md_content = "\n".join(lines)
        md_path.write_text(md_content)

        # ── Optional HTML output ────────────────────────────────────
        if html:
            self._write_html_report(md_content, self.base / "engagement_report.html")

        return md_path

    @staticmethod
    def _write_html_report(markdown_text: str, html_path: Path) -> None:
        """Convert Markdown to a simple HTML file.

        Uses a basic conversion (no external dependency) — tables and
        code blocks are preserved as ``<pre>`` sections.
        """
        import html as html_mod

        escaped = html_mod.escape(markdown_text)
        body = escaped.replace("\n", "<br>\n")
        html_content = (
            "<!DOCTYPE html><html><head>"
            "<meta charset='utf-8'>"
            "<title>ReconForge Engagement Report</title>"
            "<style>body{font-family:monospace;padding:2em;max-width:80em;margin:auto}"
            "pre{background:#f4f4f4;padding:1em;overflow-x:auto}</style>"
            "</head><body>\n"
            f"{body}\n"
            "</body></html>"
        )
        html_path.write_text(html_content)
