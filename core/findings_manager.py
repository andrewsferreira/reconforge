"""ReconForge Findings Manager - Vulnerability and finding tracking.

Implements a strict classification system to reduce heuristic findings
and enforce evidence-based severity assignments.

Classification Levels (confidence):
    - confirmed: Exploited or verified vulnerability
    - high: Strong evidence of exploitability
    - medium: Moderate evidence requiring further validation
    - low: Weak evidence requiring manual verification
    - heuristic: Pattern-based detection with no concrete evidence

Severity Levels:
    - critical: Confirmed exploitable, high-impact vulnerability
    - high: Strong evidence of exploitability with significant impact
    - medium: Moderate evidence or moderate impact
    - low: Weak evidence or minimal impact
    - info: Informational, no direct security impact

Rules:
    - No high/critical severity without at least "medium" confidence
    - "heuristic" confidence caps severity at "low"
    - Parameter names and URL patterns alone do NOT constitute evidence
"""

import json
import uuid
import warnings
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
from pathlib import Path
from datetime import datetime


@dataclass
class Finding:
    """A security finding."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    finding_type: str = ""  # vulnerability, misconfiguration, exposure, credential, attack_vector, information, assessment, prioritisation
    severity: str = "info"  # critical, high, medium, low, info
    confidence: str = "medium"  # confirmed, high, medium, low, heuristic
    target: str = ""
    module: str = ""
    phase: str = ""
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ── Severity validation rules ───────────────────────────────────────
# Maps confidence levels to the maximum allowed severity.
# "heuristic" findings are capped at "low", preventing false high/critical.
_CONFIDENCE_SEVERITY_CAP: Dict[str, str] = {
    "confirmed": "critical",   # No cap
    "high":      "critical",   # No cap
    "medium":    "high",       # Medium confidence allows up to high
    "low":       "medium",     # Low confidence caps at medium
    "heuristic": "low",        # Heuristic caps at low
}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CONFIDENCE_RANK = {"confirmed": 0, "high": 1, "medium": 2, "low": 3, "heuristic": 4}


def _clamp_severity(severity: str, confidence: str) -> str:
    """Enforce severity cap based on confidence level.

    If the requested severity exceeds what the confidence level permits,
    the severity is downgraded to the maximum allowed value.

    Returns:
        The (possibly clamped) severity string.
    """
    sev_rank = _SEVERITY_RANK.get(severity, 4)
    cap = _CONFIDENCE_SEVERITY_CAP.get(confidence, "low")
    cap_rank = _SEVERITY_RANK.get(cap, 3)

    if sev_rank < cap_rank:
        # Severity is higher than what confidence allows → clamp
        clamped = [s for s, r in _SEVERITY_RANK.items() if r == cap_rank][0]
        return clamped
    return severity


class FindingsManager:
    """Track and manage all security findings with strict classification."""

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
    VALID_CONFIDENCES = {"confirmed", "high", "medium", "low", "heuristic"}

    def __init__(self, strict: bool = True):
        """Initialise the findings manager.

        Args:
            strict: When True (default), enforce severity/confidence
                    validation rules. Findings with heuristic confidence
                    will be capped at 'low' severity.
        """
        self._findings: List[Finding] = []
        self._strict = strict
        self._clamped_count = 0

    def add(self, finding_type: str, severity: str, confidence: str,
            target: str, module: str, description: str,
            evidence: str = "", recommendation: str = "",
            phase: str = "", references: Optional[List[str]] = None) -> Finding:
        """Add a finding with automatic severity validation.

        If ``strict`` mode is enabled (the default), the severity will be
        clamped based on the confidence level to prevent weak signals
        from being reported as high/critical.

        Args:
            finding_type: Category of finding.
            severity: Requested severity level.
            confidence: Evidence confidence level.
            target: Target URL/host.
            module: Source module name.
            description: Human-readable description.
            evidence: Supporting evidence string.
            recommendation: Remediation recommendation.
            phase: Phase that generated the finding.
            references: External reference URLs.

        Returns:
            The created Finding object (severity may have been adjusted).
        """
        # Normalise inputs
        severity = severity.lower().strip()
        confidence = confidence.lower().strip()

        # Validate
        if severity not in self.VALID_SEVERITIES:
            warnings.warn(f"Unknown severity '{severity}', defaulting to 'info'")
            severity = "info"
        if confidence not in self.VALID_CONFIDENCES:
            warnings.warn(f"Unknown confidence '{confidence}', defaulting to 'low'")
            confidence = "low"

        # Apply strict clamping
        if self._strict:
            original = severity
            severity = _clamp_severity(severity, confidence)
            if severity != original:
                self._clamped_count += 1
                # Append note to description so the operator knows
                description = f"[severity clamped: {original}→{severity}] {description}"

        f = Finding(
            finding_type=finding_type, severity=severity, confidence=confidence,
            target=target, module=module, phase=phase, description=description,
            evidence=evidence, recommendation=recommendation,
            references=references or []
        )
        self._findings.append(f)
        return f

    @property
    def clamped_count(self) -> int:
        """Number of findings whose severity was clamped by validation."""
        return self._clamped_count

    def get_all(self) -> List[Finding]:
        """Get all findings sorted by severity."""
        return sorted(self._findings, key=lambda f: self.SEVERITY_ORDER.get(f.severity, 99))

    def get_by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self._findings if f.severity == severity]

    def get_by_confidence(self, confidence: str) -> List[Finding]:
        """Get findings filtered by confidence level."""
        return [f for f in self._findings if f.confidence == confidence]

    def get_by_module(self, module: str) -> List[Finding]:
        return [f for f in self._findings if f.module == module]

    def get_heuristic_findings(self) -> List[Finding]:
        """Get all findings with heuristic confidence (pattern-only detections)."""
        return [f for f in self._findings if f.confidence == "heuristic"]

    def count_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def count_by_confidence(self) -> Dict[str, int]:
        """Count findings grouped by confidence level."""
        counts: Dict[str, int] = {}
        for f in self._findings:
            counts[f.confidence] = counts.get(f.confidence, 0) + 1
        return counts

    def to_json(self) -> str:
        return json.dumps([asdict(f) for f in self.get_all()], indent=2)

    def to_markdown(self) -> str:
        lines = ["# Security Findings\n"]
        counts = self.count_by_severity()
        conf_counts = self.count_by_confidence()
        lines.append(f"**Total:** {len(self._findings)} findings")

        if self._clamped_count:
            lines.append(f"**Severity Clamped:** {self._clamped_count} findings had severity reduced due to low confidence")
        lines.append("")

        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in counts:
                lines.append(f"- **{sev.upper()}:** {counts[sev]}")
        lines.append("")

        # Confidence breakdown
        lines.append("### Confidence Breakdown")
        for conf in ["confirmed", "high", "medium", "low", "heuristic"]:
            if conf in conf_counts:
                lines.append(f"- **{conf}:** {conf_counts[conf]}")
        lines.append("")

        for f in self.get_all():
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(f.severity, "⚪")
            lines.append(f"## {icon} [{f.severity.upper()}] {f.description}")
            lines.append(f"- **ID:** {f.id}")
            lines.append(f"- **Type:** {f.finding_type}")
            lines.append(f"- **Target:** {f.target}")
            lines.append(f"- **Confidence:** {f.confidence}")
            lines.append(f"- **Module:** {f.module} / {f.phase}")
            if f.evidence:
                lines.append(f"- **Evidence:**\n```\n{f.evidence}\n```")
            if f.recommendation:
                lines.append(f"- **Recommendation:** {f.recommendation}")
            if f.references:
                lines.append("- **References:**")
                for ref in f.references:
                    lines.append(f"  - {ref}")
            lines.append("")

        return "\n".join(lines)

    def save_json(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json())

    def save_markdown(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_markdown())
