"""Reporting-domain models for structured exports and rendering."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.schemas.contracts import CorrelationResult, EvidenceItem, ExecutionResult, NormalizedObservation


@dataclass(frozen=True)
class ReportingMetadata:
    run_id: str
    generated_at: str
    generated_by: str
    target: str
    scope_id: str = ""
    approval_id: str = ""
    orchestrator_version: str = "phase5"


@dataclass(frozen=True)
class ErrorSummary:
    code: str
    message: str
    source: str
    related_ids: List[str] = field(default_factory=list)


@dataclass
class ReportingBundle:
    metadata: ReportingMetadata
    execution_results: List[ExecutionResult] = field(default_factory=list)
    normalized_observations: List[NormalizedObservation] = field(default_factory=list)
    correlated_findings: List[CorrelationResult] = field(default_factory=list)
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    inferred_commentary: List[str] = field(default_factory=list)
    llm_narrative: Optional[str] = None
    errors: List[ErrorSummary] = field(default_factory=list)

    def evidence_index(self) -> Dict[str, EvidenceItem]:
        return {item.evidence_id: item for item in self.evidence_items}

    def confidence_average(self) -> float:
        if not self.correlated_findings:
            return 0.0
        total = sum(max(0.0, min(1.0, finding.confidence)) for finding in self.correlated_findings)
        return round(total / len(self.correlated_findings), 4)

    def priority_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.correlated_findings:
            key = finding.priority if finding.priority in counts else "info"
            counts[key] += 1
        return counts
