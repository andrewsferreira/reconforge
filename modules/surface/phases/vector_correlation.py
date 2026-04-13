"""ReconForge - Surface Phase 3: Intelligent Vector Correlation

Author: Andrews Ferreira

Correlates discovered ports, services, and URLs into a unified
attack surface map using the intelligence engine. Replaces the
previous static HIGH_VALUE_SERVICES lookup with dynamic correlation,
normalization, deduplication, and confidence scoring.
"""

import json
from typing import Any, Dict, List

from modules.surface.base import SurfacePhaseBase
from modules.surface.intelligence.service_intelligence import ServiceIntelligenceDB
from modules.surface.intelligence.service_normalizer import ServiceNormalizer
from modules.surface.intelligence.correlation_engine import (
    AttackSurfaceMap,
    CorrelationEngine,
)
from modules.surface.intelligence.deduplicator import ServiceDeduplicator
from modules.surface.intelligence.confidence_scorer import ConfidenceScorer


class VectorCorrelationPhase(SurfacePhaseBase):
    """Phase 3 – Intelligent attack vector correlation.

    Transforms raw port/service data into a correlated, deduplicated,
    and enriched attack surface map with confidence scoring.
    """

    PHASE_NUMBER = 3
    PHASE_NAME = "vector_correlation"
    PHASE_DESCRIPTION = "Intelligent attack vector correlation & surface mapping"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._intel_db = ServiceIntelligenceDB()
        self._normalizer = ServiceNormalizer(self._intel_db)
        self._correlator = CorrelationEngine(self._intel_db, self._normalizer)
        self._deduplicator = ServiceDeduplicator()
        self._scorer = ConfidenceScorer(port_map=self._intel_db.port_map)

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute intelligent vector correlation phase.

        Args:
            target: Target IP / hostname.
            **kwargs: Must include 'ports' and 'services' from prior phases.

        Returns:
            Dict with attack surface map, vectors, confidence scores, and metadata.
        """
        ports = kwargs.get("ports", [])
        services = kwargs.get("services", [])
        http_services = kwargs.get("http_services", [])

        results: Dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "vectors": [],
            "surface_map": {},
            "confidence_scores": {},
            "dedup_stats": {},
            "finding_count": 0,
            "success": False,
        }

        finding_count = 0

        # ── Step 1: Deduplicate raw data ─────────────────────────────
        deduped_services = self._deduplicator.deduplicate_ports(ports, services)
        deduped_http = self._deduplicator.deduplicate_http(http_services)

        results["dedup_stats"] = {
            "ports_input": len(ports),
            "services_input": len(services),
            "http_input": len(http_services),
            "deduped_services": len(deduped_services),
            "deduped_http": len(deduped_http),
            "duplicates_removed": (len(ports) + len(services)) - len(deduped_services),
        }

        self.logger.info(
            f"Deduplication: {results['dedup_stats']['duplicates_removed']} "
            f"duplicate entries merged"
        )

        # ── Step 2: Correlate into unified attack surface map ────────
        surface_map: AttackSurfaceMap = self._correlator.correlate(
            target=target,
            ports=deduped_services,
            services=[],  # already merged into deduped_services
            http_services=deduped_http,
        )

        # ── Step 3: Score confidence for each service ────────────────
        confidence_results = self._scorer.score_batch(surface_map.services)
        for name, conf in confidence_results.items():
            svc = surface_map.services[name]
            svc.confidence = conf.score

        results["confidence_scores"] = {
            name: {"score": cr.score, "label": cr.label, "explanation": cr.explanation}
            for name, cr in confidence_results.items()
        }

        # ── Step 4: Generate findings and vectors ────────────────────
        for name, svc in surface_map.services.items():
            conf = confidence_results.get(name)
            conf_label = conf.label if conf else "medium"
            conf_score = conf.score if conf else 0.5

            # Build vector entry (backward-compatible with old format)
            vector = {
                "service": svc.canonical_name,
                "display_name": svc.display_name,
                "ports": sorted(set(svc.ports)),
                "port": svc.ports[0] if svc.ports else 0,
                "version": svc.best_version,
                "category": svc.category,
                "interest": "high" if svc.high_value else "medium",
                "risk": "high" if svc.high_value else "medium",
                "confidence": conf_label,
                "confidence_score": conf_score,
                "note": svc.attack_context,
                "detection_methods": sorted(svc.detection_methods),
                "next_steps": svc.next_steps,
                "tools": svc.common_tools,
                "urls": svc.urls,
                "flags": [],
            }

            if svc.cleartext:
                vector["flags"].append("cleartext")
            if svc.default_creds:
                vector["flags"].append("default_creds")
            if svc.high_value:
                vector["flags"].append("high_value")

            results["vectors"].append(vector)

            # Informational finding for each correlated service
            port_str = ", ".join(str(p) for p in sorted(set(svc.ports)))
            desc = (
                f"{svc.display_name} on port(s) {port_str} – "
                f"{svc.attack_context or 'Service detected'}"
            )

            self.add_finding(
                finding_type="information",
                severity="info",
                confidence=conf_label,
                target=f"{target}:{svc.ports[0]}" if svc.ports else target,
                description=desc,
                evidence=(
                    f"Service: {svc.canonical_name}, "
                    f"Version: {svc.best_version or 'unknown'}, "
                    f"Detection: {', '.join(sorted(svc.detection_methods))}, "
                    f"Confidence: {conf_label} ({conf_score:.0%})"
                ),
                recommendation=svc.next_steps[0] if svc.next_steps else (
                    f"Investigate {svc.display_name} service further."
                ),
            )
            finding_count += 1

            # Flag findings for cleartext protocols
            if svc.cleartext:
                self.add_finding(
                    finding_type="vulnerability",
                    severity="medium",
                    confidence=conf_label,
                    target=f"{target}:{svc.ports[0]}" if svc.ports else target,
                    description=(
                        f"Cleartext protocol: {svc.display_name} transmits "
                        f"data unencrypted on port(s) {port_str}"
                    ),
                    evidence=f"Protocol: {svc.canonical_name} is a cleartext protocol",
                    recommendation=(
                        f"Replace {svc.display_name} with encrypted alternative. "
                        f"Monitor for credential interception."
                    ),
                )
                finding_count += 1

            # Attack workflow suggestions for high-value services
            if svc.high_value and svc.next_steps:
                self.workflow.add_attack_path(
                    name=f"{svc.display_name} Investigation ({port_str})",
                    description=svc.attack_context,
                    steps=list(svc.next_steps[:5]),
                    risk="high" if svc.high_value else "medium",
                )

        # ── Step 5: Generate tool suggestions ────────────────────────
        self._suggest_tools(target, surface_map, http_services=deduped_http)

        # ── Step 6: Serialize ────────────────────────────────────────
        results["surface_map"] = surface_map.to_dict()
        results["finding_count"] = finding_count
        results["success"] = True

        parsed_file = self.phase_output("vector_correlation_results.json")
        parsed_file.write_text(json.dumps(results, indent=2, default=str))

        # Save separate attack surface map
        map_file = self.phase_output("attack_surface_map.json")
        map_file.write_text(json.dumps(surface_map.to_dict(), indent=2, default=str))

        return results

    def _suggest_tools(self, target: str, surface_map: AttackSurfaceMap,
                       http_services: list) -> None:
        """Suggest next-step tools based on correlated services."""
        service_names = set(surface_map.services.keys())

        tool_suggestions = {
            "smb": (
                f"enum4linux-ng -A {target}",
                "SMB detected – enumerate shares, users, policies, signing",
                "high",
            ),
            "ldap": (
                f"ldapsearch -x -H ldap://{target} -b '' -s base namingContexts",
                "LDAP detected – test anonymous bind and enumerate AD",
                "high",
            ),
            "kerberos": (
                f"kerbrute userenum -d DOMAIN --dc {target} users.txt",
                "Kerberos detected – enumerate valid usernames for Kerberoasting",
                "high",
            ),
            "ssh": (
                f"ssh-audit {target}",
                "SSH detected – audit algorithms, config, and version",
                "medium",
            ),
            "rdp": (
                f"nmap --script rdp-ntlm-info -p 3389 {target}",
                "RDP detected – extract NTLM info and check NLA",
                "high",
            ),
            "mssql": (
                f"impacket-mssqlclient -windows-auth {target}",
                "MSSQL detected – test for default credentials and xp_cmdshell",
                "high",
            ),
            "mysql": (
                f"mysql -h {target} -u root --password=''",
                "MySQL detected – test for empty root password",
                "medium",
            ),
            "redis": (
                f"redis-cli -h {target} INFO",
                "Redis detected – test for unauthenticated access",
                "high",
            ),
            "ftp": (
                f"ftp {target}",
                "FTP detected – test for anonymous access",
                "medium",
            ),
            "snmp": (
                f"onesixtyone -c community.txt {target}",
                "SNMP detected – brute-force community strings",
                "medium",
            ),
        }

        for svc_name, (cmd, justification, priority) in tool_suggestions.items():
            if svc_name in service_names:
                self.workflow.suggest_next(
                    command=cmd,
                    justification=justification,
                    priority=priority,
                )

        if http_services:
            self.workflow.suggest_next(
                command=f"nuclei -u {target} -severity critical,high,medium",
                justification="HTTP services detected – run vulnerability templates",
                priority="high",
            )
            self.workflow.suggest_next(
                command=f"ffuf -u http://{target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt",
                justification="HTTP services detected – directory/file brute-force",
                priority="medium",
            )
