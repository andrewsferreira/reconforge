"""ReconForge - Intelligent Attack Prioritizer

Author: Andrews Ferreira

Provides meaningful prioritization that goes beyond numeric scores.
Groups services by attack category, highlights high-value targets,
and provides actionable next steps for each service.
"""

from dataclasses import dataclass, field
from typing import Any

from modules.surface.intelligence.confidence_scorer import ConfidenceResult, ConfidenceScorer
from modules.surface.intelligence.correlation_engine import (
    AttackSurfaceMap,
    CorrelatedService,
)


@dataclass
class PrioritizedTarget:
    """A prioritized target with actionable context."""
    rank: int
    canonical_name: str
    display_name: str
    ports: list[int]
    category: str
    priority_level: str  # critical, high, medium, low
    confidence: str  # confirmed, high, medium, low
    confidence_score: float
    attack_context: str
    next_steps: list[str]
    tools: list[str]
    version: str = ""
    urls: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)  # e.g., ["cleartext", "default_creds"]
    rationale: str = ""  # Why this priority level

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank": self.rank,
            "canonical_name": self.canonical_name,
            "display_name": self.display_name,
            "ports": self.ports,
            "category": self.category,
            "priority_level": self.priority_level,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
            "attack_context": self.attack_context,
            "next_steps": self.next_steps,
            "tools": self.tools,
            "version": self.version,
            "urls": self.urls,
            "flags": self.flags,
            "rationale": self.rationale,
        }


@dataclass
class CategoryGroup:
    """Grouped services by attack category."""
    category: str
    display_name: str
    targets: list[PrioritizedTarget] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "display_name": self.display_name,
            "target_count": len(self.targets),
            "summary": self.summary,
            "targets": [t.to_dict() for t in self.targets],
        }


@dataclass
class PrioritizationResult:
    """Complete prioritization output."""
    ranked_targets: list[PrioritizedTarget] = field(default_factory=list)
    category_groups: list[CategoryGroup] = field(default_factory=list)
    executive_summary: str = ""
    quick_wins: list[PrioritizedTarget] = field(default_factory=list)
    high_value_targets: list[PrioritizedTarget] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "executive_summary": self.executive_summary,
            "total_targets": len(self.ranked_targets),
            "quick_wins": [t.to_dict() for t in self.quick_wins],
            "high_value_targets": [t.to_dict() for t in self.high_value_targets],
            "ranked_targets": [t.to_dict() for t in self.ranked_targets],
            "category_groups": [g.to_dict() for g in self.category_groups],
        }


# Category display names and investigation order
CATEGORY_ORDER = [
    ("ad", "Active Directory"),
    ("database", "Databases"),
    ("remote_access", "Remote Access"),
    ("web", "Web Services"),
    ("file_sharing", "File Sharing"),
    ("mail", "Mail Services"),
    ("monitoring", "Monitoring & Management"),
    ("misc", "Miscellaneous"),
]

# Priority calculation weights
PRIORITY_WEIGHTS = {
    "high_value": 3.0,
    "default_creds": 2.0,
    "cleartext": 1.5,
    "version_known": 1.0,
    "category_ad": 2.5,
    "category_database": 2.0,
    "category_remote_access": 1.5,
    "category_web": 1.0,
}


class AttackPrioritizer:
    """Intelligent attack surface prioritizer.

    Produces actionable prioritization instead of just numeric scores:
    - Groups by attack category
    - Identifies quick wins (default creds, no-auth services)
    - Highlights high-value targets (DCs, databases, admin interfaces)
    - Provides next steps and tool suggestions
    """

    def __init__(self, confidence_scorer: ConfidenceScorer | None = None) -> None:
        self._scorer = confidence_scorer

    def prioritize(
        self,
        surface_map: AttackSurfaceMap,
        confidence_results: dict[str, ConfidenceResult] | None = None,
    ) -> PrioritizationResult:
        """Generate intelligent prioritization from the attack surface map.

        Args:
            surface_map: Correlated attack surface map.
            confidence_results: Pre-computed confidence scores (optional).

        Returns:
            PrioritizationResult with ranked targets and category groups.
        """
        result = PrioritizationResult()
        all_targets: list[PrioritizedTarget] = []

        for name, svc in surface_map.services.items():
            conf = confidence_results.get(name) if confidence_results else None
            target = self._build_target(svc, conf)
            all_targets.append(target)

        # Sort by priority score (computed from priority_level + confidence)
        all_targets.sort(key=lambda t: self._sort_key(t), reverse=True)

        # Assign ranks
        for i, t in enumerate(all_targets, 1):
            t.rank = i

        result.ranked_targets = all_targets

        # Build category groups
        result.category_groups = self._build_category_groups(all_targets)

        # Identify quick wins
        result.quick_wins = [
            t for t in all_targets
            if "default_creds" in t.flags or "cleartext" in t.flags or "no_auth_possible" in t.flags
        ][:5]

        # Identify high-value targets
        result.high_value_targets = [
            t for t in all_targets if t.priority_level in ("critical", "high")
        ][:10]

        # Executive summary
        result.executive_summary = self._build_executive_summary(
            surface_map, all_targets
        )

        return result

    def _build_target(
        self, svc: CorrelatedService, conf: ConfidenceResult | None
    ) -> PrioritizedTarget:
        """Build a PrioritizedTarget from a CorrelatedService."""
        flags = []
        if svc.cleartext:
            flags.append("cleartext")
        if svc.default_creds:
            flags.append("default_creds")
        if svc.high_value:
            flags.append("high_value")

        # Compute priority level
        priority_level = self._compute_priority(svc, flags)

        # Build rationale
        rationale = self._build_rationale(svc, priority_level, flags)

        return PrioritizedTarget(
            rank=0,  # assigned later
            canonical_name=svc.canonical_name,
            display_name=svc.display_name or svc.canonical_name.upper(),
            ports=sorted(set(svc.ports)),
            category=svc.category or "misc",
            priority_level=priority_level,
            confidence=conf.label if conf else "medium",
            confidence_score=conf.score if conf else 0.5,
            attack_context=svc.attack_context,
            next_steps=svc.next_steps[:5],
            tools=svc.common_tools[:5],
            version=svc.best_version,
            urls=svc.urls[:10],
            flags=flags,
            rationale=rationale,
        )

    def _compute_priority(self, svc: CorrelatedService, flags: list[str]) -> str:
        """Compute priority level based on service characteristics."""
        score = 0.0

        if svc.high_value:
            score += PRIORITY_WEIGHTS["high_value"]
        if svc.default_creds:
            score += PRIORITY_WEIGHTS["default_creds"]
        if svc.cleartext:
            score += PRIORITY_WEIGHTS["cleartext"]
        if svc.best_version:
            score += PRIORITY_WEIGHTS["version_known"]

        cat_key = f"category_{svc.category}"
        score += PRIORITY_WEIGHTS.get(cat_key, 0.5)

        if score >= 6.0:
            return "critical"
        elif score >= 4.0:
            return "high"
        elif score >= 2.0:
            return "medium"
        else:
            return "low"

    @staticmethod
    def _build_rationale(svc: CorrelatedService, level: str, flags: list[str]) -> str:
        """Build human-readable rationale for priority assignment."""
        reasons = []
        if svc.high_value:
            reasons.append("high-value target")
        if svc.default_creds:
            reasons.append("commonly has default credentials")
        if svc.cleartext:
            reasons.append("cleartext protocol (credential interception)")
        if svc.best_version:
            reasons.append(f"version {svc.best_version} detected (check for CVEs)")
        if svc.category == "ad":
            reasons.append("Active Directory service (domain-level impact)")
        elif svc.category == "database":
            reasons.append("database service (data access impact)")

        if not reasons:
            reasons.append("standard service detected")

        return f"{level.upper()} priority: {'; '.join(reasons)}"

    def _build_category_groups(self, targets: list[PrioritizedTarget]) -> list[CategoryGroup]:
        """Group targets by attack category."""
        groups_dict: dict[str, list[PrioritizedTarget]] = {}
        for t in targets:
            groups_dict.setdefault(t.category, []).append(t)

        result = []
        for cat_key, cat_display in CATEGORY_ORDER:
            if cat_key in groups_dict:
                group = CategoryGroup(
                    category=cat_key,
                    display_name=cat_display,
                    targets=groups_dict[cat_key],
                    summary=self._category_summary(cat_key, groups_dict[cat_key]),
                )
                result.append(group)

        # Any categories not in CATEGORY_ORDER
        for cat_key, targets_list in groups_dict.items():
            if not any(cat_key == co[0] for co in CATEGORY_ORDER):
                result.append(CategoryGroup(
                    category=cat_key,
                    display_name=cat_key.replace("_", " ").title(),
                    targets=targets_list,
                ))

        return result

    @staticmethod
    def _category_summary(category: str, targets: list[PrioritizedTarget]) -> str:
        """Generate summary for a category group."""
        high_prio = sum(1 for t in targets if t.priority_level in ("critical", "high"))
        summaries = {
            "ad": f"{len(targets)} AD service(s) detected. {high_prio} high-priority. Focus on domain enumeration and credential attacks.",
            "database": f"{len(targets)} database(s) detected. {high_prio} high-priority. Test for default credentials and data access.",
            "remote_access": f"{len(targets)} remote access service(s). {high_prio} high-priority. Test for credential attacks and CVEs.",
            "web": f"{len(targets)} web service(s). {high_prio} high-priority. Run web scanning and directory enumeration.",
            "file_sharing": f"{len(targets)} file service(s). Test for anonymous access and sensitive data.",
            "mail": f"{len(targets)} mail service(s). Check for user enumeration and open relay.",
            "monitoring": f"{len(targets)} management service(s). Test for default credentials and information disclosure.",
        }
        return summaries.get(category, f"{len(targets)} service(s) detected.")

    @staticmethod
    def _sort_key(target: PrioritizedTarget) -> float:
        """Compute sort key for ranking."""
        level_scores = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}
        base = level_scores.get(target.priority_level, 1.0)
        return base + target.confidence_score

    @staticmethod
    def _build_executive_summary(
        surface_map: AttackSurfaceMap, targets: list[PrioritizedTarget]
    ) -> str:
        """Generate executive summary text."""
        total = len(targets)
        hv = surface_map.high_value_count
        critical = sum(1 for t in targets if t.priority_level == "critical")
        high = sum(1 for t in targets if t.priority_level == "high")
        cats = {t.category for t in targets}

        lines = [
            f"Attack surface analysis identified {total} unique service(s) "
            f"across {surface_map.total_ports} open port(s).",
        ]

        if hv:
            lines.append(f"{hv} high-value target(s) detected.")
        if critical or high:
            lines.append(
                f"{critical + high} service(s) rated critical/high priority "
                f"({critical} critical, {high} high)."
            )

        cat_display = {
            "ad": "Active Directory",
            "database": "Databases",
            "remote_access": "Remote Access",
            "web": "Web",
            "file_sharing": "File Sharing",
            "mail": "Mail",
            "monitoring": "Monitoring",
        }
        active_cats = [cat_display.get(c, c) for c in sorted(cats)]
        if active_cats:
            lines.append(f"Service categories: {', '.join(active_cats)}.")

        return " ".join(lines)
