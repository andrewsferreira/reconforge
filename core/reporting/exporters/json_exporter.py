"""Machine-readable reporting exports.

Exports are intentionally stable and split by layer:
- execution summary
- normalized observations
- correlated findings
- evidence references
- errors and limitations
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from core.reporting.models import ReportingBundle
from core.reporting.serializers.json_serializer import dump_json, to_jsonable


class JsonReportingExporter:
    schema_version = "1.0"

    def export(self, bundle: ReportingBundle, output_dir: Path) -> Dict[str, Path]:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        payloads: Dict[str, Dict[str, Any]] = {
            "execution_summary": self._execution_summary(bundle),
            "normalized_observations": self._normalized_observations(bundle),
            "correlated_findings": self._correlated_findings(bundle),
            "evidence_references": self._evidence_references(bundle),
            "error_summary": self._error_summary(bundle),
            "run_metadata": self._run_metadata(bundle),
        }

        written: Dict[str, Path] = {}
        for name, payload in payloads.items():
            path = output_dir / f"{name}.json"
            path.write_text(dump_json(payload), encoding="utf-8")
            written[name] = path

        return written

    def _run_metadata(self, bundle: ReportingBundle) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_metadata": to_jsonable(bundle.metadata),
        }

    def _execution_summary(self, bundle: ReportingBundle) -> Dict[str, Any]:
        status_counts: Dict[str, int] = {"success": 0, "failed": 0, "blocked": 0}
        for result in bundle.execution_results:
            status = result.status if result.status in status_counts else "failed"
            status_counts[status] += 1

        return {
            "schema_version": self.schema_version,
            "run_id": bundle.metadata.run_id,
            "target": bundle.metadata.target,
            "execution_count": len(bundle.execution_results),
            "execution_status_counts": status_counts,
            "observation_count": len(bundle.normalized_observations),
            "correlated_finding_count": len(bundle.correlated_findings),
            "priority_counts": bundle.priority_counts(),
            "average_confidence": bundle.confidence_average(),
        }

    def _normalized_observations(self, bundle: ReportingBundle) -> Dict[str, Any]:
        by_target: Dict[str, int] = {}
        for obs in bundle.normalized_observations:
            by_target[obs.target] = by_target.get(obs.target, 0) + 1

        return {
            "schema_version": self.schema_version,
            "run_id": bundle.metadata.run_id,
            "items": [to_jsonable(obs) for obs in bundle.normalized_observations],
            "counts_by_target": by_target,
        }

    def _correlated_findings(self, bundle: ReportingBundle) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": bundle.metadata.run_id,
            "items": [to_jsonable(f) for f in bundle.correlated_findings],
            "priority_counts": bundle.priority_counts(),
        }

    def _evidence_references(self, bundle: ReportingBundle) -> Dict[str, Any]:
        ref_graph = []
        for finding in bundle.correlated_findings:
            ref_graph.append({
                "target": finding.target,
                "finding_keys": list(finding.finding_keys),
                "evidence_ids": list(finding.evidence_ids),
            })

        return {
            "schema_version": self.schema_version,
            "run_id": bundle.metadata.run_id,
            "evidence_items": [to_jsonable(item) for item in bundle.evidence_items],
            "finding_to_evidence": ref_graph,
        }

    def _error_summary(self, bundle: ReportingBundle) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": bundle.metadata.run_id,
            "errors": [to_jsonable(e) for e in bundle.errors],
            "limitations": list(bundle.limitations),
        }
