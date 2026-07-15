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
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from core.cve_enricher import enrich_references
from core.data_contracts import build_contract


@dataclass
class Finding:
    """A security finding."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    finding_type: str = ""  # vulnerability, misconfiguration, exposure, credential, attack_vector, information, assessment, prioritisation
    severity: str = "info"  # critical, high, medium, low, info
    confidence: str = "medium"  # confirmed, high, medium, low, heuristic
    confidence_reason: str = ""  # why this confidence level was chosen (optional)
    target: str = ""
    module: str = ""
    phase: str = ""
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ── Severity validation rules ───────────────────────────────────────
# Maps confidence levels to the maximum allowed severity.
# "heuristic" findings are capped at "low", preventing false high/critical.
_CONFIDENCE_SEVERITY_CAP: dict[str, str] = {
    "confirmed": "critical",   # No cap
    "high":      "critical",   # No cap
    "medium":    "high",       # Medium confidence allows up to high
    "low":       "medium",     # Low confidence caps at medium
    "heuristic": "low",        # Heuristic caps at low
}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


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
        self._findings: list[Finding] = []
        self._strict = strict
        self._clamped_count = 0
        self._duplicate_count = 0
        self._seen: dict[str, Finding] = {}  # fingerprint -> first-seen Finding

    def add(self, finding_type: str, severity: str, confidence: str,
            target: str, module: str, description: str,
            evidence: str = "", recommendation: str = "",
            phase: str = "", references: list[str] | None = None,
            confidence_reason: str = "") -> Finding:
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
            confidence_reason: Optional explanation of why this confidence
                level was chosen (e.g. "actively exploited via sqlmap" vs
                "graph-inferred attack path, not verified"). Callers are
                not required to set this yet — most existing call sites
                don't — but new/updated call sites should prefer it over
                a bare confidence literal with no justification.

        Returns:
            The created Finding object (severity may have been adjusted),
            or the first-seen Finding if this call is an exact duplicate
            of one already recorded (see ``duplicate_count``).
        """
        # Normalise inputs
        severity = severity.lower().strip()
        confidence = confidence.lower().strip()

        # Validate
        if severity not in self.VALID_SEVERITIES:
            warnings.warn(f"Unknown severity '{severity}', defaulting to 'info'", stacklevel=2)
            severity = "info"
        if confidence not in self.VALID_CONFIDENCES:
            warnings.warn(f"Unknown confidence '{confidence}', defaulting to 'low'", stacklevel=2)
            confidence = "low"

        # Apply strict clamping
        if self._strict:
            original = severity
            severity = _clamp_severity(severity, confidence)
            if severity != original:
                self._clamped_count += 1
                # Append note to description so the operator knows
                description = f"[severity clamped: {original}→{severity}] {description}"

        # Exact-duplicate check, before enrich_references() (which can hit
        # the network) so a repeated call does no wasted work. Modeled on
        # core/credential_vault.py::CredentialVault._fingerprint()'s
        # proven O(1) set-based pattern. Deliberately narrow (exact-match
        # on finding_type/severity/confidence/target/description) — it
        # catches the same call being made twice (the class of bug found
        # in modules/network/phases/authentication_checks.py and
        # modules/network/parsers/nmap_parser.py), not semantically-similar
        # findings worded differently by different tools, which is a
        # separate, harder problem left for a future correlation pass.
        fp = self._fingerprint(finding_type, severity, confidence, target, description)
        existing = self._seen.get(fp)
        if existing is not None:
            self._duplicate_count += 1
            return existing

        f = Finding(
            finding_type=finding_type, severity=severity, confidence=confidence,
            confidence_reason=confidence_reason,
            target=target, module=module, phase=phase, description=description,
            evidence=evidence, recommendation=recommendation,
            references=enrich_references(description, evidence, references or [])
        )
        self._seen[fp] = f
        self._findings.append(f)
        return f

    @staticmethod
    def _fingerprint(finding_type: str, severity: str, confidence: str,
                     target: str, description: str) -> str:
        """Unique fingerprint for exact-duplicate detection."""
        return f"{finding_type}|{severity}|{confidence}|{target}|{description}"

    def ingest(self, other: "FindingsManager") -> int:
        """Merge another FindingsManager's findings into this one.

        Re-runs each finding through ``add()`` (not a raw list extend),
        so this instance's own exact-duplicate dedup applies — e.g. two
        modules independently reporting the identical SMB-signing
        misconfiguration for the same target during a workflow's
        auto-handoff collapse into one entry here, the same as if a
        single module had called ``add()`` twice. Severity re-clamping
        is a no-op for already-valid values, so this is safe to call
        even when ``other`` was itself built in non-strict mode.

        Args:
            other: The FindingsManager to merge from (unmodified).

        Returns:
            The number of findings actually added (excludes duplicates
            that were already present in this manager).
        """
        added = 0
        for f in other.get_all():
            before = len(self._findings)
            self.add(
                finding_type=f.finding_type, severity=f.severity,
                confidence=f.confidence, confidence_reason=f.confidence_reason,
                target=f.target, module=f.module, phase=f.phase,
                description=f.description, evidence=f.evidence,
                recommendation=f.recommendation, references=list(f.references),
            )
            if len(self._findings) > before:
                added += 1
        return added

    @property
    def clamped_count(self) -> int:
        """Number of findings whose severity was clamped by validation."""
        return self._clamped_count

    @property
    def duplicate_count(self) -> int:
        """Number of add() calls that matched an already-recorded finding."""
        return self._duplicate_count

    def get_all(self) -> list[Finding]:
        """Get all findings sorted by severity."""
        return sorted(self._findings, key=lambda f: self.SEVERITY_ORDER.get(f.severity, 99))

    def get_by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self._findings if f.severity == severity]

    def get_by_confidence(self, confidence: str) -> list[Finding]:
        """Get findings filtered by confidence level."""
        return [f for f in self._findings if f.confidence == confidence]

    def get_by_module(self, module: str) -> list[Finding]:
        return [f for f in self._findings if f.module == module]

    def get_heuristic_findings(self) -> list[Finding]:
        """Get all findings with heuristic confidence (pattern-only detections)."""
        return [f for f in self._findings if f.confidence == "heuristic"]

    def count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def count_by_confidence(self) -> dict[str, int]:
        """Count findings grouped by confidence level."""
        counts: dict[str, int] = {}
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
        if self._duplicate_count:
            lines.append(f"**Duplicates Merged:** {self._duplicate_count} exact-duplicate add() calls were collapsed into their first-seen finding")
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

        heuristic_findings = self.get_heuristic_findings()
        if heuristic_findings:
            lines.append(
                f"### Heuristic Findings ({len(heuristic_findings)}) — pattern-based, no concrete evidence"
            )
            lines.append(
                "These findings are capped at 'low' severity and require manual verification before acting on them.\n"
            )
            for f in heuristic_findings:
                lines.append(f"- **[{f.severity.upper()}]** {f.description} (`{f.id}`)")
            lines.append("")

        for f in self.get_all():
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(f.severity, "⚪")
            lines.append(f"## {icon} [{f.severity.upper()}] {f.description}")
            lines.append(f"- **ID:** {f.id}")
            lines.append(f"- **Type:** {f.finding_type}")
            lines.append(f"- **Target:** {f.target}")
            lines.append(f"- **Confidence:** {f.confidence}")
            if f.confidence_reason:
                lines.append(f"- **Confidence Reason:** {f.confidence_reason}")
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

    def save_contract(self, path: Path, execution_id: str = "", module: str = ""):
        payload = [asdict(f) for f in self.get_all()]
        contract = build_contract("findings", payload, execution_id=execution_id, module=module)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(contract, indent=2))

    def save_markdown(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_markdown())
