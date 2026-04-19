"""Reporting pipeline orchestrator for Phase 5 outputs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from core.reporting.exporters.json_exporter import JsonReportingExporter
from core.reporting.exporters.manifest_builder import ReportManifestBuilder
from core.reporting.models import ReportingBundle
from core.reporting.renderers.executive_summary import ExecutiveSummaryRenderer
from core.reporting.renderers.technical_markdown import TechnicalMarkdownRenderer


class ReportingPipeline:
    """Generate structured reporting artifacts under a deterministic layout."""

    def __init__(
        self,
        json_exporter: JsonReportingExporter | None = None,
        technical_renderer: TechnicalMarkdownRenderer | None = None,
        executive_renderer: ExecutiveSummaryRenderer | None = None,
        manifest_builder: ReportManifestBuilder | None = None,
    ):
        self.json_exporter = json_exporter or JsonReportingExporter()
        self.technical_renderer = technical_renderer or TechnicalMarkdownRenderer()
        self.executive_renderer = executive_renderer or ExecutiveSummaryRenderer()
        self.manifest_builder = manifest_builder or ReportManifestBuilder()

    def generate(self, bundle: ReportingBundle, base_output_dir: Path) -> Dict[str, Path]:
        root = Path(base_output_dir) / "reporting"
        raw_dir = root / "raw"
        normalized_dir = root / "normalized"
        correlated_dir = root / "correlated"
        reports_dir = root / "reports"
        manifests_dir = root / "manifests"
        for d in [raw_dir, normalized_dir, correlated_dir, reports_dir, manifests_dir]:
            d.mkdir(parents=True, exist_ok=True)

        artifacts: Dict[str, Path] = {}

        json_outputs = self.json_exporter.export(bundle, root / "structured")
        artifacts.update({f"structured:{k}": v for k, v in json_outputs.items()})

        raw_path = raw_dir / "raw_results.json"
        raw_path.write_text(self._dump_raw(bundle), encoding="utf-8")
        artifacts["raw:raw_results"] = raw_path

        norm_path = normalized_dir / "normalized_observations.json"
        norm_path.write_text(json_outputs["normalized_observations"].read_text(encoding="utf-8"), encoding="utf-8")
        artifacts["normalized:observations"] = norm_path

        corr_path = correlated_dir / "correlated_findings.json"
        corr_path.write_text(json_outputs["correlated_findings"].read_text(encoding="utf-8"), encoding="utf-8")
        artifacts["correlated:findings"] = corr_path

        technical_path = reports_dir / "technical_report.md"
        technical_path.write_text(self.technical_renderer.render(bundle), encoding="utf-8")
        artifacts["reports:technical"] = technical_path

        executive_path = reports_dir / "executive_summary.md"
        executive_path.write_text(self.executive_renderer.render(bundle), encoding="utf-8")
        artifacts["reports:executive"] = executive_path

        manifest_path = manifests_dir / "report_manifest.json"
        self.manifest_builder.build(bundle.metadata.run_id, artifacts, manifest_path)
        artifacts["manifests:report_manifest"] = manifest_path

        return artifacts

    @staticmethod
    def _dump_raw(bundle: ReportingBundle) -> str:
        import json
        from dataclasses import asdict

        payload = {
            "run_id": bundle.metadata.run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "execution_results": [asdict(r) for r in bundle.execution_results],
        }
        return json.dumps(payload, indent=2, sort_keys=True)
