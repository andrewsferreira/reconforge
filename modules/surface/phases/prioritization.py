"""ReconForge - Surface Phase 4: Intelligent Prioritization

Author: Andrews Ferreira

Prioritizes the attack surface using the intelligence engine to produce
actionable, category-grouped, and meaningfully scored recommendations.
Replaces the old flat numeric scoring with intelligent prioritization.
"""

import json
from typing import Any, Dict, List, Optional

from modules.surface.base import SurfacePhaseBase
from modules.surface.intelligence.service_intelligence import ServiceIntelligenceDB
from modules.surface.intelligence.correlation_engine import (
    AttackSurfaceMap,
    CorrelationEngine,
)
from modules.surface.intelligence.confidence_scorer import ConfidenceScorer, ConfidenceResult
from modules.surface.intelligence.attack_prioritizer import (
    AttackPrioritizer,
    PrioritizationResult,
)


class PrioritizationPhase(SurfacePhaseBase):
    """Phase 4 – Intelligent attack surface prioritization.

    Produces:
    - Ranked targets with actionable context
    - Category-grouped recommendations
    - Quick wins (default creds, cleartext, no-auth)
    - High-value targets (DCs, databases, admin interfaces)
    - Executive summary with clear next steps
    """

    PHASE_NUMBER = 4
    PHASE_NAME = "prioritization"
    PHASE_DESCRIPTION = "Intelligent attack surface prioritization & action plan"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._intel_db = ServiceIntelligenceDB()
        self._scorer = ConfidenceScorer(port_map=self._intel_db.port_map)
        self._prioritizer = AttackPrioritizer(confidence_scorer=self._scorer)

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute intelligent prioritization phase.

        Args:
            target: Target IP / hostname.
            **kwargs: Must include 'vectors', 'ports', 'http_services',
                     and optionally 'surface_map' and 'confidence_scores'
                     from Phase 3.

        Returns:
            Dict with prioritized actions, category groups, and metadata.
        """
        vectors = kwargs.get("vectors", [])
        ports = kwargs.get("ports", [])
        http_services = kwargs.get("http_services", [])
        surface_map_data = kwargs.get("surface_map", {})
        confidence_data = kwargs.get("confidence_scores", {})

        results: Dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "prioritised_actions": [],
            "category_groups": [],
            "quick_wins": [],
            "high_value_targets": [],
            "executive_summary": "",
            "summary": {},
            "finding_count": 0,
            "success": False,
        }

        finding_count = 0

        # Reconstruct AttackSurfaceMap from Phase 3 data if available
        if surface_map_data and isinstance(surface_map_data, dict):
            surface_map = self._reconstruct_surface_map(surface_map_data)
        else:
            # Fallback: build from vectors (backward compatibility)
            surface_map = self._build_surface_map_from_vectors(target, vectors)

        # Reconstruct confidence results
        confidence_results: Dict[str, ConfidenceResult] = {}
        if confidence_data:
            for name, cd in confidence_data.items():
                confidence_results[name] = ConfidenceResult(
                    score=cd.get("score", 0.5),
                    label=cd.get("label", "medium"),
                    signals={},
                    explanation=cd.get("explanation", ""),
                )
        else:
            # Re-score if no confidence data from Phase 3
            confidence_results = self._scorer.score_batch(surface_map.services)

        # ── Run intelligent prioritization ────────────────────────────
        prio_result: PrioritizationResult = self._prioritizer.prioritize(
            surface_map, confidence_results
        )

        # ── Generate findings for top prioritized targets ─────────────
        for target_entry in prio_result.ranked_targets[:10]:
            severity = self._priority_to_severity(target_entry.priority_level)
            port_str = ", ".join(str(p) for p in target_entry.ports)

            self.add_finding(
                finding_type="prioritisation",
                severity=severity,
                confidence=target_entry.confidence,
                target=f"{target}:{target_entry.ports[0]}" if target_entry.ports else target,
                description=(
                    f"Priority #{target_entry.rank}: {target_entry.display_name} "
                    f"on port(s) {port_str} "
                    f"[{target_entry.priority_level.upper()}]"
                ),
                evidence=target_entry.rationale,
                recommendation=(
                    target_entry.next_steps[0] if target_entry.next_steps
                    else f"Investigate {target_entry.display_name} further."
                ),
            )
            finding_count += 1

        # ── Quick wins finding ────────────────────────────────────────
        if prio_result.quick_wins:
            qw_names = [t.display_name for t in prio_result.quick_wins]
            self.add_finding(
                finding_type="assessment",
                severity="medium",
                confidence="high",
                target=target,
                description=(
                    f"Quick wins identified: {', '.join(qw_names)} – "
                    f"services likely vulnerable to default credentials, "
                    f"anonymous access, or cleartext interception"
                ),
                evidence=json.dumps([t.to_dict() for t in prio_result.quick_wins], default=str),
                recommendation=(
                    "Start with quick wins: test default credentials, "
                    "anonymous access, and cleartext interception."
                ),
            )
            finding_count += 1

        # ── Executive summary finding ─────────────────────────────────
        if prio_result.executive_summary:
            total_critical = sum(
                1 for t in prio_result.ranked_targets if t.priority_level == "critical"
            )
            total_high = sum(
                1 for t in prio_result.ranked_targets if t.priority_level == "high"
            )
            investigate = total_critical + total_high

            self.add_finding(
                finding_type="assessment",
                severity="info",
                confidence="high",
                target=target,
                description=prio_result.executive_summary,
                evidence=json.dumps({
                    "total_services": len(prio_result.ranked_targets),
                    "critical": total_critical,
                    "high": total_high,
                    "categories": [g.category for g in prio_result.category_groups],
                }),
                recommendation=(
                    f"Focus on {investigate} high-priority target(s). "
                    f"Review category-grouped action plan for systematic approach."
                ) if investigate else "Review all identified services for potential issues.",
            )
            finding_count += 1

        # ── Populate results ──────────────────────────────────────────
        results["prioritised_actions"] = [t.to_dict() for t in prio_result.ranked_targets]
        results["category_groups"] = [g.to_dict() for g in prio_result.category_groups]
        results["quick_wins"] = [t.to_dict() for t in prio_result.quick_wins]
        results["high_value_targets"] = [t.to_dict() for t in prio_result.high_value_targets]
        results["executive_summary"] = prio_result.executive_summary

        # Summary statistics (backward compatible)
        priority_counts: Dict[str, int] = {}
        for t in prio_result.ranked_targets:
            priority_counts[t.priority_level] = priority_counts.get(t.priority_level, 0) + 1

        results["summary"] = {
            "total_ports": len(ports),
            "total_vectors": len(vectors),
            "total_http_services": len(http_services),
            "total_services": len(prio_result.ranked_targets),
            "priority_breakdown": priority_counts,
            "categories": {g.category: len(g.targets) for g in prio_result.category_groups},
            "high_value_count": len(prio_result.high_value_targets),
            "quick_win_count": len(prio_result.quick_wins),
        }

        results["finding_count"] = finding_count
        results["success"] = True

        # Save results
        parsed_file = self.phase_output("prioritization_results.json")
        parsed_file.write_text(json.dumps(results, indent=2, default=str))

        # Save prioritized action plan as markdown
        self._save_action_plan(target, prio_result)

        return results

    def _save_action_plan(self, target: str, prio: PrioritizationResult) -> None:
        """Save a human-readable prioritized action plan."""
        lines = [
            "# Attack Surface Action Plan",
            f"**Target:** {target}",
            "",
            "## Executive Summary",
            prio.executive_summary,
            "",
        ]

        if prio.quick_wins:
            lines.append("## Quick Wins (Start Here)")
            for t in prio.quick_wins:
                flags = ", ".join(t.flags) if t.flags else "none"
                lines.append(f"### #{t.rank} {t.display_name} (ports: {', '.join(str(p) for p in t.ports)})")
                lines.append(f"- **Priority:** {t.priority_level.upper()}")
                lines.append(f"- **Flags:** {flags}")
                lines.append(f"- **Rationale:** {t.rationale}")
                if t.next_steps:
                    lines.append("- **Next Steps:**")
                    for step in t.next_steps:
                        lines.append(f"  1. {step}")
                if t.tools:
                    lines.append(f"- **Tools:** {', '.join(t.tools)}")
                lines.append("")

        for group in prio.category_groups:
            lines.append(f"## {group.display_name}")
            if group.summary:
                lines.append(f"*{group.summary}*")
                lines.append("")

            for t in group.targets:
                lines.append(f"### #{t.rank} {t.display_name} [{t.priority_level.upper()}]")
                lines.append(f"- **Ports:** {', '.join(str(p) for p in t.ports)}")
                lines.append(f"- **Confidence:** {t.confidence} ({t.confidence_score:.0%})")
                if t.version:
                    lines.append(f"- **Version:** {t.version}")
                if t.urls:
                    lines.append(f"- **URLs:** {', '.join(t.urls[:5])}")
                lines.append(f"- **Context:** {t.attack_context}")
                if t.next_steps:
                    lines.append("- **Next Steps:**")
                    for step in t.next_steps:
                        lines.append(f"  1. {step}")
                if t.tools:
                    lines.append(f"- **Tools:** {', '.join(t.tools)}")
                lines.append("")

        plan_file = self.phase_output("action_plan.md")
        plan_file.write_text("\n".join(lines))

    @staticmethod
    def _priority_to_severity(priority: str) -> str:
        """Map priority level to finding severity."""
        mapping = {
            "critical": "high",
            "high": "medium",
            "medium": "low",
            "low": "info",
        }
        return mapping.get(priority, "info")

    def _reconstruct_surface_map(self, data: Dict) -> AttackSurfaceMap:
        """Reconstruct an AttackSurfaceMap from serialized Phase 3 data."""
        from modules.surface.intelligence.correlation_engine import (
            AttackSurfaceMap,
            CorrelatedService,
        )

        surface = AttackSurfaceMap(
            target=data.get("target", ""),
            total_ports=data.get("total_ports", 0),
            total_services=data.get("total_services", 0),
            high_value_count=data.get("high_value_count", 0),
            by_category=data.get("by_category", {}),
        )

        for name, svc_data in data.get("services", {}).items():
            svc = CorrelatedService(
                canonical_name=svc_data.get("canonical_name", name),
                display_name=svc_data.get("display_name", ""),
                ports=svc_data.get("ports", []),
                protocols=svc_data.get("protocols", []),
                versions=svc_data.get("all_versions", []),
                products=svc_data.get("products", []),
                urls=svc_data.get("urls", []),
                technologies=svc_data.get("technologies", []),
                detection_methods=set(svc_data.get("detection_methods", [])),
                category=svc_data.get("category", ""),
                attack_context=svc_data.get("attack_context", ""),
                next_steps=svc_data.get("next_steps", []),
                common_tools=svc_data.get("common_tools", []),
                high_value=svc_data.get("high_value", False),
                cleartext=svc_data.get("cleartext", False),
                default_creds=svc_data.get("default_creds", False),
                confidence=svc_data.get("confidence", 0.5),
            )
            surface.services[name] = svc

        return surface

    def _build_surface_map_from_vectors(self, target: str, vectors: List[Dict]) -> AttackSurfaceMap:
        """Build an AttackSurfaceMap from old-style vector dicts (backward compat)."""
        from modules.surface.intelligence.correlation_engine import (
            AttackSurfaceMap,
            CorrelatedService,
        )

        surface = AttackSurfaceMap(target=target)
        for v in vectors:
            name = v.get("service", "unknown")
            ports = v.get("ports", [v.get("port", 0)])
            ports = [p for p in ports if p]

            svc = CorrelatedService(
                canonical_name=name,
                display_name=v.get("display_name", name.upper()),
                ports=ports,
                category=v.get("category", "misc"),
                attack_context=v.get("note", ""),
                next_steps=v.get("next_steps", []),
                common_tools=v.get("tools", []),
                high_value="high_value" in v.get("flags", []),
                cleartext="cleartext" in v.get("flags", []),
                default_creds="default_creds" in v.get("flags", []),
                confidence=v.get("confidence_score", 0.5),
            )

            if v.get("version"):
                svc.versions.append(v["version"])

            surface.services[name] = svc

        surface.total_services = len(surface.services)
        all_ports = set()
        for s in surface.services.values():
            all_ports.update(s.ports)
        surface.total_ports = len(all_ports)
        surface.high_value_count = sum(1 for s in surface.services.values() if s.high_value)

        return surface
