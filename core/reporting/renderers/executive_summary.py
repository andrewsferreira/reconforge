"""Executive summary renderer grounded in correlated findings."""

from __future__ import annotations

from typing import List

from core.reporting.models import ReportingBundle


class ExecutiveSummaryRenderer:
    def render(self, bundle: ReportingBundle) -> str:
        lines: List[str] = []
        lines.append("# ReconForge Executive Summary\n")
        lines.append("## Scope and Run Context")
        lines.append(f"- Run ID: `{bundle.metadata.run_id}`")
        lines.append(f"- Target: `{bundle.metadata.target}`")
        lines.append(f"- Scope ID: `{bundle.metadata.scope_id or 'N/A'}`")
        lines.append(f"- Approval ID: `{bundle.metadata.approval_id or 'N/A'}`")
        lines.append("")

        priority_counts = bundle.priority_counts()
        lines.append("## Major Finding Clusters (Correlated Layer)")
        lines.append(f"- Critical: `{priority_counts['critical']}`")
        lines.append(f"- High: `{priority_counts['high']}`")
        lines.append(f"- Medium: `{priority_counts['medium']}`")
        lines.append(f"- Low: `{priority_counts['low']}`")
        lines.append(f"- Info: `{priority_counts['info']}`")
        lines.append("")

        lines.append("## Confidence and Data Quality")
        lines.append(f"- Average correlated confidence: `{bundle.confidence_average():.2f}`")
        lines.append(f"- Evidence items recorded: `{len(bundle.evidence_items)}`")
        lines.append(f"- Normalized observations: `{len(bundle.normalized_observations)}`")
        lines.append("")

        lines.append("## Operational Limitations")
        if bundle.limitations:
            for limitation in bundle.limitations:
                lines.append(f"- {limitation}")
        else:
            lines.append("- No explicit limitations were recorded in this run.")
        lines.append("")

        lines.append("## Next Actions (Evidence-Grounded)")
        if bundle.correlated_findings:
            ranked = sorted(bundle.correlated_findings, key=lambda f: (f.priority, -f.confidence))
            for finding in ranked[:5]:
                lines.append(
                    f"- Validate target `{finding.target}` finding set `{', '.join(finding.finding_keys) or 'N/A'}` "
                    f"using evidence IDs: {', '.join(finding.evidence_ids) or 'none'}"
                )
        else:
            lines.append("- No correlated findings to prioritize.")
        lines.append("")

        lines.append("## Interpretation Notice")
        lines.append("- This summary is derived from normalized observations and correlated findings.")
        lines.append("- It does not replace technical evidence review.")
        lines.append("- No exploitability or business impact is asserted without supporting evidence.")

        return "\n".join(lines).strip() + "\n"
