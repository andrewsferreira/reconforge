"""Technical markdown report renderer with explicit traceability."""

from __future__ import annotations

from collections import Counter
from typing import List

from core.reporting.models import ReportingBundle


class TechnicalMarkdownRenderer:
    def render(self, bundle: ReportingBundle) -> str:
        lines: List[str] = []
        lines.append("# ReconForge Technical Run Report\n")
        lines.append("## Run Metadata")
        lines.append(f"- Run ID: `{bundle.metadata.run_id}`")
        lines.append(f"- Generated At: `{bundle.metadata.generated_at}`")
        lines.append(f"- Target: `{bundle.metadata.target}`")
        lines.append(f"- Scope ID: `{bundle.metadata.scope_id or 'N/A'}`")
        lines.append(f"- Approval ID: `{bundle.metadata.approval_id or 'N/A'}`")
        lines.append("")

        lines.extend(self._render_run_summary(bundle))
        lines.extend(self._render_target_service_summary(bundle))
        lines.extend(self._render_observations(bundle))
        lines.extend(self._render_findings(bundle))
        lines.extend(self._render_errors_and_limitations(bundle))
        lines.extend(self._render_fact_vs_inference(bundle))
        return "\n".join(lines).strip() + "\n"

    def _render_run_summary(self, bundle: ReportingBundle) -> List[str]:
        status_counter = Counter(result.status for result in bundle.execution_results)
        lines = ["## Run Summary"]
        lines.append(f"- Executions: `{len(bundle.execution_results)}`")
        lines.append(f"- Success: `{status_counter.get('success', 0)}`")
        lines.append(f"- Failed: `{status_counter.get('failed', 0)}`")
        lines.append(f"- Blocked: `{status_counter.get('blocked', 0)}`")
        lines.append(f"- Normalized Observations: `{len(bundle.normalized_observations)}`")
        lines.append(f"- Correlated Findings: `{len(bundle.correlated_findings)}`")
        lines.append("")
        return lines

    def _render_target_service_summary(self, bundle: ReportingBundle) -> List[str]:
        lines = ["## Target and Service Summary"]
        target_counter = Counter(obs.target for obs in bundle.normalized_observations)
        service_counter: Counter[str] = Counter()
        for obs in bundle.normalized_observations:
            service = str(obs.attributes.get("service", "")).strip().lower()
            if service:
                service_counter[service] += 1

        if target_counter:
            lines.append("### Targets")
            for target, count in sorted(target_counter.items()):
                lines.append(f"- `{target}`: {count} observations")
        else:
            lines.append("- No normalized targets recorded.")

        if service_counter:
            lines.append("\n### Services")
            for service, count in service_counter.most_common():
                lines.append(f"- `{service}`: {count}")
        else:
            lines.append("\n- No service fingerprints observed in normalized data.")

        lines.append("")
        return lines

    def _render_observations(self, bundle: ReportingBundle) -> List[str]:
        lines = ["## Normalized Observation Summary"]
        if not bundle.normalized_observations:
            lines.append("- No normalized observations available.")
            lines.append("")
            return lines

        for obs in bundle.normalized_observations:
            lines.append(f"- Type: `{obs.observation_type}` | Target: `{obs.target}` | Evidence: `{obs.evidence_id or 'N/A'}`")
        lines.append("")
        return lines

    def _render_findings(self, bundle: ReportingBundle) -> List[str]:
        lines = ["## Correlated Findings"]
        if not bundle.correlated_findings:
            lines.append("- No correlated findings were produced.")
            lines.append("")
            return lines

        evidence_map = bundle.evidence_index()
        for finding in bundle.correlated_findings:
            lines.append(f"### Target `{finding.target}` [{finding.priority.upper()}]")
            lines.append(f"- Confidence: `{finding.confidence:.2f}`")
            lines.append(f"- Finding Keys: `{', '.join(finding.finding_keys) or 'N/A'}`")
            if finding.evidence_ids:
                lines.append("- Evidence References:")
                for evidence_id in finding.evidence_ids:
                    status = evidence_map.get(evidence_id).status if evidence_id in evidence_map else "missing"
                    lines.append(f"  - `{evidence_id}` (status: {status})")
            else:
                lines.append("- Evidence References: none")
            lines.append("")
        return lines

    def _render_errors_and_limitations(self, bundle: ReportingBundle) -> List[str]:
        lines = ["## Error and Limitation Summary"]
        if bundle.errors:
            lines.append("### Errors")
            for error in bundle.errors:
                lines.append(f"- [{error.code}] {error.message} (source: {error.source})")
        else:
            lines.append("- No execution/reporting errors recorded.")

        if bundle.limitations:
            lines.append("\n### Limitations")
            for limitation in bundle.limitations:
                lines.append(f"- {limitation}")
        else:
            lines.append("\n- No explicit limitations captured.")

        lines.append("")
        return lines

    def _render_fact_vs_inference(self, bundle: ReportingBundle) -> List[str]:
        lines = ["## Fact vs Interpretation Boundary"]
        lines.append("### Observed Facts (Structured)")
        lines.append("- Execution results, normalized observations, correlated findings, and evidence references are factual output layers.")

        lines.append("\n### Inferred Commentary")
        if bundle.inferred_commentary:
            for item in bundle.inferred_commentary:
                lines.append(f"- {item}")
        else:
            lines.append("- None")

        lines.append("\n### LLM Narrative (Derived, Non-Authoritative)")
        lines.append(f"- {bundle.llm_narrative if bundle.llm_narrative else 'None'}")
        lines.append("")
        return lines
