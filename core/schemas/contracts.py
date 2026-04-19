"""Canonical typed schemas for orchestration foundations.

These contracts are intentionally small and explicit so they can be adopted
incrementally by existing modules without breaking current execution paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

ActionClass = Literal[
    "discovery",
    "enumeration",
    "fingerprinting",
    "enrichment",
    "correlation",
    "reporting",
]
ExecutionMode = Literal["safe", "standard", "extended"]


@dataclass(frozen=True)
class Target:
    """Normalized target contract consumed by policy validators."""

    value: str
    kind: Literal["domain", "subdomain", "ip", "cidr", "url", "hostname", "unknown"] = "unknown"


@dataclass(frozen=True)
class ExecutionRequest:
    """High-level request to execute one orchestrated action."""

    run_id: str
    initiated_by: str
    target: Target
    provider: str
    action: str
    action_class: ActionClass
    mode: ExecutionMode = "safe"
    dry_run: bool = False
    timeout_seconds: int = 300
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvidenceItem:
    """Evidence record with lineage metadata."""

    evidence_id: str
    run_id: str
    timestamp: str
    provider: str
    target: str
    action: str
    raw_ref: str
    normalized_ref: str = ""
    correlation_ref: str = ""
    status: Literal["success", "failed", "blocked"] = "success"
    error: str = ""


@dataclass(frozen=True)
class NormalizedObservation:
    """Normalized provider observation used by correlators and reporters."""

    observation_type: Literal["service_fingerprint", "http", "dns", "asset", "enrichment", "generic"]
    target: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    evidence_id: str = ""


@dataclass(frozen=True)
class CorrelationResult:
    """Correlated outcome preserving evidence lineage."""

    target: str
    finding_keys: List[str] = field(default_factory=list)
    confidence: float = 0.0
    priority: Literal["critical", "high", "medium", "low", "info"] = "info"
    evidence_ids: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ExecutionResult:
    """Deterministic result envelope returned by orchestrator coordinator."""

    run_id: str
    provider: str
    target: str
    action: str
    status: Literal["success", "failed", "blocked"]
    started_at: str
    finished_at: str
    duration_seconds: float
    raw_result: Dict[str, Any] = field(default_factory=dict)
    normalized: List[NormalizedObservation] = field(default_factory=list)
    error: str = ""

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ReportEntry:
    """Structured report entry with explicit narrative provenance."""

    target: str
    summary: str
    evidence_ids: List[str] = field(default_factory=list)
    correlated_keys: List[str] = field(default_factory=list)
    llm_narrative: Optional[str] = None
