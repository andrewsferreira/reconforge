"""ReconForge AD Analyzer — Trust relationship analysis.

Author: Andrews Ferreira

Analyzes domain/forest trust relationships for risk and
lateral movement opportunities.
"""

from typing import Any

from modules.ad.analyzers.base import AnalysisResult, AnalyzerBase


class TrustAnalyzer(AnalyzerBase):
    """Analyze domain and forest trust relationships."""

    ANALYZER_NAME = "trusts"

    def analyze(self, collected_data: dict[str, Any], **kwargs) -> AnalysisResult:
        """Analyze trust relationships.

        Expected keys:
            - trusts: list of trust dicts (partner, direction, type, flat_name)
        """
        target = kwargs.get("target", "")
        result = AnalysisResult(analyzer=self.ANALYZER_NAME)

        trusts = collected_data.get("trusts", [])
        if not trusts:
            return result

        result.data["trust_count"] = len(trusts)
        result.data["trusts"] = trusts

        # Overall finding
        trust_summary = ", ".join(
            f"{t['partner']} ({t['direction']})" for t in trusts
        )
        result.findings.append(self._make_finding(
            finding_type="exposure",
            severity="medium",
            confidence="confirmed",
            target=target,
            description=f"Domain trust relationships discovered ({len(trusts)})",
            evidence=trust_summary,
            recommendation=(
                "Review trust relationships — disable unnecessary trusts. "
                "Enable SID filtering on external trusts."
            ),
            references=["https://attack.mitre.org/techniques/T1482/"],
            phase="configuration_enumeration",
        ))

        # Bidirectional trust risk
        bidirectional = [t for t in trusts if "bidirectional" in t.get("direction", "").lower()]
        if bidirectional:
            result.insights.append(
                f"{len(bidirectional)} bidirectional trust(s) — "
                "higher lateral movement risk"
            )
            result.data["bidirectional_trusts"] = bidirectional

        # External/forest trusts
        external = [t for t in trusts if "external" in t.get("type", "").lower()
                    or "forest" in t.get("type", "").lower()]
        if external:
            result.insights.append(
                f"{len(external)} external/forest trust(s) — "
                "cross-boundary attack surface"
            )
            result.data["external_trusts"] = external

        return result
