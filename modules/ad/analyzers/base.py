"""ReconForge AD Analyzer Base — shared interface for all analyzers.

Author: Andrews Ferreira
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AnalysisResult:
    """Standardised output from any analyzer.

    Attributes:
        analyzer: Name of the analyzer that produced the result.
        findings: List of finding dicts ready for FindingsManager.
        insights: Free-form analysis insights.
        data: Additional structured data.
    """
    analyzer: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    insights: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


class AnalyzerBase(ABC):
    """Abstract base for all AD analyzers."""

    ANALYZER_NAME: str = "base"

    @abstractmethod
    def analyze(self, collected_data: dict[str, Any], **kwargs) -> AnalysisResult:
        """Analyze collected data and return structured results."""
        ...

    def _make_finding(
        self,
        finding_type: str,
        severity: str,
        confidence: str,
        target: str,
        description: str,
        evidence: str = "",
        recommendation: str = "",
        references: list[str] | None = None,
        phase: str = "",
    ) -> dict[str, Any]:
        """Helper to build a finding dict."""
        return {
            "finding_type": finding_type,
            "severity": severity,
            "confidence": confidence,
            "target": target,
            "module": "ad",
            "phase": phase,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "references": references or [],
        }
