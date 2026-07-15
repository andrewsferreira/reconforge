"""Rule-based correlation and prioritization layer for adaptive workflows.

This module upgrades ReconForge from static phase orchestration to a
deterministic decision engine (fixed keyword rules, hand-written confidence
literals, a linear weighted score — no ML/LLM, see
docs/AI_ORCHESTRATION_ARCHITECTURE.md's status note) that correlates
findings across modules, constructs an attack graph, scores exploitability,
and recommends next actions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

_SEVERITY_SCORE = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 1}
_CONFIDENCE_SCORE = {"confirmed": 1.0, "high": 0.9, "medium": 0.7, "low": 0.5, "heuristic": 0.3}
# Matches reconforge/mcp/schemas.py::MODULE_NAMES / core/workflow_orchestrator.py's
# add_full_recon() ordering: broad-surface modules before narrower ones.
_MODULE_ORDER = ("surface", "network", "ad", "web", "api")

# Lightweight mapping for immediate hypotheses without external lookups.
_BANNER_CVE_HINTS: dict[str, list[str]] = {
    "openssh 7": ["CVE-2018-15473"],
    "apache 2.4.49": ["CVE-2021-41773"],
    "samba 3": ["CVE-2017-7494"],
    "microsoft-iis/7.5": ["CVE-2015-1635"],
}


@dataclass
class CorrelatedSignal:
    """Normalized finding enriched for decision and triage."""

    source_module: str
    signal_type: str
    target: str
    evidence: str
    severity: str = "info"
    confidence: str = "low"
    exploit_likelihood: float = 0.1
    reachability: float = 0.1
    asset_criticality: float = 0.5
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    finding_id: str = ""

    def risk_score(self) -> float:
        sev = _SEVERITY_SCORE.get(self.severity, 1) / 10.0
        conf = _CONFIDENCE_SCORE.get(self.confidence, 0.5)
        return round((
            0.35 * sev
            + 0.30 * self.exploit_likelihood
            + 0.20 * self.reachability
            + 0.15 * self.asset_criticality
        ) * conf * 100, 2)


@dataclass
class AttackGraph:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)

    def add_node(self, node_id: str, node_type: str, **attrs: Any) -> None:
        current = self.nodes.setdefault(node_id, {"id": node_id, "type": node_type})
        current.update(attrs)

    def add_edge(self, from_node: str, to_node: str, relation: str, weight: float = 0.5) -> None:
        edge = {
            "from": from_node,
            "to": to_node,
            "relation": relation,
            "weight": weight,
        }
        if edge not in self.edges:
            self.edges.append(edge)


class AIOrchestrationLayer:
    """Central intelligence, context builder, and adaptive decision engine."""

    def __init__(self):
        self.signals: list[CorrelatedSignal] = []
        self.graph = AttackGraph()
        self.hypotheses: list[dict[str, Any]] = []

    # ---- ingestion (tool/module adapters) ---------------------------------

    def ingest_module_result(self, module_name: str, result: dict[str, Any]) -> list[CorrelatedSignal]:
        parsers = {
            "network": self._ingest_network,
            "surface": self._ingest_surface,
            "web": self._ingest_web,
            "api": self._ingest_api,
            "ad": self._ingest_ad,
        }
        parser = parsers.get(module_name)
        if not parser:
            return []
        created = parser(result)
        self.signals.extend(created)
        return created

    def ingest_nmap_scan(self, hosts_data: dict[str, Any]) -> list[CorrelatedSignal]:
        """Direct Nmap ingestion for parsed structures from nmap parser/output."""
        result = {"phases": {"scanning": {"hosts": hosts_data}}}
        created = self._ingest_network(result)
        self.signals.extend(created)
        return created

    def ingest_proxy_logs(self, proxy_events: list[dict[str, Any]]) -> list[CorrelatedSignal]:
        """Burp/proxy log ingestion for request-response security signals."""
        created: list[CorrelatedSignal] = []
        for event in proxy_events:
            host = str(event.get("host", "unknown"))
            path = str(event.get("path", "/"))
            status = int(event.get("status", 0) or 0)
            headers = {str(k).lower(): str(v) for k, v in (event.get("response_headers") or {}).items()}

            self.graph.add_node(host, "host")
            endpoint = f"{host}{path}"
            self.graph.add_node(endpoint, "endpoint", status=status)
            self.graph.add_edge(host, endpoint, "serves")

            if "content-security-policy" not in headers:
                created.append(CorrelatedSignal(
                    source_module="proxy",
                    signal_type="missing_header",
                    target=endpoint,
                    evidence="Missing Content-Security-Policy header in observed response.",
                    severity="low",
                    confidence="high",
                    exploit_likelihood=0.35,
                    reachability=0.9,
                    tags=["http", "header", "csp"],
                ))
            if status in {401, 403} and "x-debug" in headers:
                created.append(CorrelatedSignal(
                    source_module="proxy",
                    signal_type="debug_header_exposure",
                    target=endpoint,
                    evidence="Debug headers exposed on denied endpoint; indicates verbose backend behavior.",
                    severity="medium",
                    confidence="medium",
                    exploit_likelihood=0.45,
                    reachability=0.8,
                    tags=["authz", "debug"],
                ))
        self.signals.extend(created)
        return created

    def ingest_http_scan(self, scan_events: list[dict[str, Any]]) -> list[CorrelatedSignal]:
        """HTTP scanner ingestion for behavior-level hypotheses."""
        created: list[CorrelatedSignal] = []
        for event in scan_events:
            url = str(event.get("url", ""))
            issue = str(event.get("issue", ""))
            severity = str(event.get("severity", "low")).lower()
            if not url:
                continue
            self.graph.add_node(url, "endpoint")
            created.append(CorrelatedSignal(
                source_module="http_scanner",
                signal_type="scanner_issue",
                target=url,
                evidence=issue or "Scanner-reported behavior anomaly.",
                severity=severity if severity in _SEVERITY_SCORE else "low",
                confidence="medium",
                exploit_likelihood=0.5 if severity in {"high", "critical"} else 0.3,
                reachability=0.8,
                tags=["http", "scanner"],
            ))
        self.signals.extend(created)
        return created

    def ingest_findings(self, findings: list[dict[str, Any]]) -> list[CorrelatedSignal]:
        """Ingest already-persisted Finding records (core/findings_manager.py's
        on-disk findings.json schema: id/finding_type/severity/confidence/
        target/module/description/references).

        This is the only ingestion path available to a stateless MCP tool
        call: unlike core/workflow_orchestrator.py's WorkflowOrchestrator,
        which holds one AIOrchestrationLayer instance in memory across an
        entire multi-step run and feeds it each module's raw run() result
        via ingest_module_result(), an MCP-driven execution
        (reconforge/mcp/services.py::execute_approved_phase) runs one
        module/phase per call and never holds that in-memory result past
        the call — the module's findings.json is the only surviving
        cross-call artifact. exploit_likelihood/reachability here are
        fixed, documented defaults derived from severity, not a learned
        or predicted value (see docs/AI_ORCHESTRATION_ARCHITECTURE.md).
        """
        created: list[CorrelatedSignal] = []
        for raw in findings:
            target = str(raw.get("target", "")) or "unknown"
            module = str(raw.get("module", ""))
            severity = str(raw.get("severity", "info")).lower()
            if severity not in _SEVERITY_SCORE:
                severity = "info"
            confidence = str(raw.get("confidence", "low")).lower()
            if confidence not in _CONFIDENCE_SCORE:
                confidence = "low"
            references = raw.get("references", [])

            self.graph.add_node(target, "finding_target")
            if module:
                self.graph.add_node(module, "module")
                self.graph.add_edge(module, target, "produced_finding", weight=0.6)

            created.append(CorrelatedSignal(
                source_module=module,
                signal_type=str(raw.get("finding_type", "information")),
                target=target,
                evidence=str(raw.get("description", "")) or str(raw.get("evidence", "")),
                severity=severity,
                confidence=confidence,
                exploit_likelihood=0.6 if severity in {"critical", "high"} else 0.3 if severity == "medium" else 0.15,
                reachability=0.7,
                references=[str(r) for r in references] if isinstance(references, list) else [],
                tags=[t for t in (module, str(raw.get("finding_type", ""))) if t],
                finding_id=str(raw.get("id", "")),
            ))
        self.signals.extend(created)
        return created

    # ---- context builder ----------------------------------------------------

    def build_context_snapshot(self) -> dict[str, Any]:
        by_target: dict[str, list[dict[str, Any]]] = {}
        for sig in self.signals:
            by_target.setdefault(sig.target, []).append(asdict(sig))

        prioritized = sorted(
            (
                {
                    "target": target,
                    "max_risk": max((s["risk_score"] if "risk_score" in s else CorrelatedSignal(**{
                        **s,
                    }).risk_score()) for s in payload),
                    "signal_count": len(payload),
                }
                for target, payload in by_target.items()
            ),
            key=lambda x: x["max_risk"],
            reverse=True,
        )

        return {
            "signals_total": len(self.signals),
            "graph": {
                "nodes": list(self.graph.nodes.values()),
                "edges": list(self.graph.edges),
            },
            "prioritized_targets": prioritized,
        }

    # ---- decision engine ----------------------------------------------------

    def decide_next_actions(self, already_planned: set[str] | None = None) -> list[dict[str, Any]]:
        already_planned = already_planned or set()
        recommendations: list[dict[str, Any]] = []

        # Port/service derived hypotheses.
        services_seen: set[str] = set()
        for node in self.graph.nodes.values():
            if node.get("type") == "service":
                services_seen.add(str(node.get("name", "")).lower())

        if {"http", "https", "http-alt"} & services_seen and "web" not in already_planned:
            recommendations.append({
                "module": "web",
                "confidence": 0.93,
                "reason": "HTTP service exposure requires endpoint and content-enumeration follow-up.",
                "priority": "high",
            })
        if {"ldap", "kerberos", "smb", "ldaps"} & services_seen and "ad" not in already_planned:
            recommendations.append({
                "module": "ad",
                "confidence": 0.9,
                "reason": "Directory/authentication services indicate likely AD attack surface.",
                "priority": "high",
            })
        if {"http", "https"} & services_seen and "api" not in already_planned:
            recommendations.append({
                "module": "api",
                "confidence": 0.72,
                "reason": "Web assets often expose APIs; trigger authentication and authorization testing.",
                "priority": "medium",
            })

        # Signal-driven exploit hypotheses.
        top = self.top_attack_paths(limit=3)
        for path in top:
            recommendations.append({
                "module": "network",
                "confidence": min(0.98, 0.5 + path["score"] / 200),
                "reason": f"Validate chain '{path['name']}' with focused service/version checks.",
                "priority": "high" if path["score"] > 65 else "medium",
            })

        return recommendations

    def top_attack_paths(self, limit: int = 5) -> list[dict[str, Any]]:
        paths: list[dict[str, Any]] = []
        for sig in self.signals:
            score = sig.risk_score()
            if score < 30:
                continue
            title = f"{sig.target} via {sig.signal_type}"
            narrative = [
                f"Establish reachability to {sig.target}.",
                f"Exploit or validate condition: {sig.evidence}",
                "Pivot to adjacent services or credential material.",
            ]
            paths.append({
                "name": title,
                "score": score,
                "target": sig.target,
                "narrative": narrative,
                "references": sig.references,
                "finding_id": sig.finding_id,
            })
        paths.sort(key=lambda x: x["score"], reverse=True)
        return paths[:limit]

    def recommend_modules(self, already_run: set[str]) -> list[dict[str, Any]]:
        """Coverage-gap module recommendation from ingested findings alone
        (see ingest_findings()) — deterministic, not a prediction.

        This is the MCP-facing counterpart to decide_next_actions(): that
        method needs raw scan data (port/service graph nodes) only the
        live CLI WorkflowOrchestrator ever holds; this one works from
        persisted findings.json records, the only signal an MCP tool call
        has access to. It answers "what hasn't been assessed yet, and
        does what we've already found raise the value of assessing it" —
        not "what will succeed."
        """
        has_signals = bool(self.signals)
        has_high_value = any(s.severity in {"critical", "high"} for s in self.signals)
        recommendations: list[dict[str, Any]] = []
        for module in _MODULE_ORDER:
            if module in already_run:
                continue
            if has_high_value:
                priority, confidence = "high", 0.8
            elif has_signals:
                priority, confidence = "medium", 0.55
            else:
                priority, confidence = "low", 0.35
            reason = f"'{module}' has not been assessed for this target yet."
            if has_high_value:
                reason += (
                    " Existing findings for already-run modules include critical/high-severity "
                    "signals, raising the value of expanding coverage before concluding the engagement."
                )
            recommendations.append({
                "module": module,
                "confidence": confidence,
                "priority": priority,
                "reason": reason,
                "already_run": False,
            })
        recommendations.sort(key=lambda r: r["confidence"], reverse=True)
        return recommendations

    def generate_ai_report(self) -> dict[str, Any]:
        top_paths = self.top_attack_paths(limit=5)
        recommendations = self._recommendations_from_paths(top_paths)
        return {
            "executive_summary": self._executive_summary(top_paths),
            "technical_findings": [self._technical_finding(sig) for sig in sorted(self.signals, key=lambda s: s.risk_score(), reverse=True)[:25]],
            "attack_narrative": top_paths,
            "recommendations": recommendations,
            "triage": self._triage_snapshot(),
        }

    # ---- internals ----------------------------------------------------------

    def _ingest_network(self, result: dict[str, Any]) -> list[CorrelatedSignal]:
        created: list[CorrelatedSignal] = []
        hosts = result.get("phases", {}).get("scanning", {}).get("hosts", {})
        for host, details in hosts.items():
            self.graph.add_node(host, "host")
            ports = details.get("open_ports", []) if isinstance(details, dict) else []
            for p in ports:
                port = p["port"] if isinstance(p, dict) else p
                service = ""
                banner = ""
                if isinstance(p, dict):
                    service = str(p.get("service", ""))
                    banner = f"{service} {p.get('version', '')}".strip()
                service_node = f"{host}:{port}"
                self.graph.add_node(service_node, "service", port=port, name=service or f"tcp/{port}", banner=banner)
                self.graph.add_edge(host, service_node, "exposes", weight=0.8)

                exploit_likelihood = 0.6 if str(port) in {"445", "3389", "3306", "5432"} else 0.35
                severity = "medium" if exploit_likelihood >= 0.5 else "low"
                refs = self._cve_hints(banner)
                if refs:
                    exploit_likelihood = min(0.95, exploit_likelihood + 0.25)
                    severity = "high"

                created.append(CorrelatedSignal(
                    source_module="network",
                    signal_type="service_exposure",
                    target=service_node,
                    evidence=f"Port {port} open {f'({banner})' if banner else ''}",
                    severity=severity,
                    confidence="high",
                    exploit_likelihood=exploit_likelihood,
                    reachability=0.95,
                    references=refs,
                    tags=["nmap", "service", service.lower() if service else "unknown"],
                ))
        return created

    def _ingest_surface(self, result: dict[str, Any]) -> list[CorrelatedSignal]:
        hosts = result.get("phases", {}).get("port_discovery", {}).get("hosts", {})
        return self._ingest_network({"phases": {"scanning": {"hosts": hosts}}})

    def _ingest_web(self, result: dict[str, Any]) -> list[CorrelatedSignal]:
        created: list[CorrelatedSignal] = []
        target = str(result.get("target", ""))
        if target:
            self.graph.add_node(target, "endpoint")
        findings = result.get("findings", []) if isinstance(result, dict) else []
        for finding in findings if isinstance(findings, list) else []:
            sev = str(finding.get("severity", "low")).lower()
            desc = str(finding.get("description", "web signal"))
            signal = CorrelatedSignal(
                source_module="web",
                signal_type=str(finding.get("type", "web_finding")),
                target=target or str(finding.get("target", "web-target")),
                evidence=desc,
                severity=sev if sev in _SEVERITY_SCORE else "low",
                confidence=str(finding.get("confidence", "medium")).lower(),
                exploit_likelihood=0.55 if sev in {"high", "critical"} else 0.35,
                reachability=0.85,
                references=list(finding.get("references", [])) if isinstance(finding.get("references"), list) else [],
                tags=["web"],
            )
            created.append(signal)
        return created

    def _ingest_api(self, result: dict[str, Any]) -> list[CorrelatedSignal]:
        created = self._ingest_web(result)
        for signal in created:
            signal.source_module = "api"
            signal.tags.append("api")
            signal.exploit_likelihood = min(0.95, signal.exploit_likelihood + 0.1)
        return created

    def _ingest_ad(self, result: dict[str, Any]) -> list[CorrelatedSignal]:
        created: list[CorrelatedSignal] = []
        domain = str(result.get("domain", ""))
        if domain:
            self.graph.add_node(domain, "domain")
            created.append(CorrelatedSignal(
                source_module="ad",
                signal_type="domain_surface",
                target=domain,
                evidence=f"Active Directory footprint discovered for {domain}.",
                severity="medium",
                confidence="high",
                exploit_likelihood=0.5,
                reachability=0.7,
                tags=["ad", "identity"],
            ))
        return created

    def _cve_hints(self, banner: str) -> list[str]:
        low_banner = (banner or "").lower()
        refs: list[str] = []
        for token, cves in _BANNER_CVE_HINTS.items():
            if token in low_banner:
                refs.extend(cves)
        return sorted(set(refs))

    def _executive_summary(self, paths: list[dict[str, Any]]) -> dict[str, Any]:
        highest = paths[0]["score"] if paths else 0
        return {
            "signals": len(self.signals),
            "graph_nodes": len(self.graph.nodes),
            "graph_edges": len(self.graph.edges),
            "top_risk_score": highest,
            "priority_message": (
                "Immediate validation of top attack paths is recommended."
                if highest >= 70 else
                "Continue adaptive reconnaissance to raise confidence before exploitation."
            ),
        }

    def _technical_finding(self, signal: CorrelatedSignal) -> dict[str, Any]:
        return {
            "target": signal.target,
            "type": signal.signal_type,
            "source": signal.source_module,
            "severity": signal.severity,
            "confidence": signal.confidence,
            "risk_score": signal.risk_score(),
            "evidence": signal.evidence,
            "references": signal.references,
        }

    def _recommendations_from_paths(self, paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
        recs: list[dict[str, Any]] = []
        for p in paths:
            priority = "P1" if p["score"] >= 75 else "P2" if p["score"] >= 55 else "P3"
            recs.append({
                "priority": priority,
                "action": f"Validate and contain path: {p['name']}",
                "rationale": f"Composite triage score {p['score']}",
            })
        return recs

    def _triage_snapshot(self) -> list[dict[str, Any]]:
        triage_rows: list[dict[str, Any]] = []
        for sig in sorted(self.signals, key=lambda s: s.risk_score(), reverse=True):
            triage_rows.append({
                "target": sig.target,
                "signal_type": sig.signal_type,
                "severity": sig.severity,
                "exploit_likelihood": sig.exploit_likelihood,
                "reachability": sig.reachability,
                "asset_criticality": sig.asset_criticality,
                "risk_score": sig.risk_score(),
            })
        return triage_rows[:50]
