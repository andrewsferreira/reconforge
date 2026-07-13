"""Attack path generation and validation engine for ReconForge."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
import json
import logging
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from reconforge.collectors.http_collector import HttpCollector
from reconforge.intelligence.engine import (
    CorrelationRelationship,
    IntelligenceReport,
    PrioritizedFinding,
    VulnerabilityClassification,
)

LOGGER = logging.getLogger(__name__)


@dataclass
class AttackPrimitive:
    type: str
    capability: str
    preconditions: list[str]
    impact: str


@dataclass
class AttackPathStep:
    step_id: str
    endpoint: str
    method: str
    parameter: str
    action: str
    expected_outcome: str
    # Finding type this step chains through (e.g. "IDOR_candidate") — used
    # by _step_corroborated() to check a type-appropriate success signal
    # instead of "the request didn't error," which any request satisfies.
    finding_type: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    path_id: str
    steps: list[AttackPathStep]
    primitive_types: list[str]
    impact: str
    confidence: float
    # Three honest tiers, matching docs/attack_path_generation.md terminology:
    #   "unreachable"   — at least one step's request errored/timed out.
    #   "reachable"     — every step got an HTTP response, but at least one
    #                     didn't match its expected success signal (e.g. a
    #                     404/403 instead of 200) — the chain could not be
    #                     replayed as hypothesized.
    #   "corroborated"  — every step both completed AND matched its
    #                     expected success signal. This is still a
    #                     heuristic replay, NOT confirmed exploitation
    #                     (that requires an actual authorized-lab
    #                     validation — see docs/FINDINGS.md) —
    #                     it means the hypothesis survived a live retest,
    #                     nothing more.
    status: str
    # DEPRECATED: True iff status == "corroborated". Kept so any existing
    # caller reading this boolean gets the *stricter* of the two possible
    # readings rather than silently breaking; new code should read `status`.
    validated: bool
    evidence: list[dict[str, Any]]
    priority: str
    score: float


@dataclass
class AttackPathGraph:
    nodes: dict[str, dict[str, Any]]
    edges: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPathReport:
    graph: AttackPathGraph
    primitives: list[AttackPrimitive]
    attack_paths: list[AttackPath]
    refinement_rounds: int
    failure_analysis: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AttackPathGenerationEngine:
    def __init__(self, collector: HttpCollector):
        self.collector = collector

    def run(self, report: IntelligenceReport, *, refinement_rounds: int = 1) -> AttackPathReport:
        self._assert_required_input(report)

        graph = self._build_graph(report)
        primitives = self._build_primitives(report.classifications)

        initial_paths = self._generate_candidate_paths(report)
        validated_paths = self._validate_paths(initial_paths)

        refined_paths = list(validated_paths)
        for _ in range(max(0, refinement_rounds)):
            if not refined_paths:
                break
            expanded = self._refine_paths(report, refined_paths)
            refined_paths = self._validate_paths(expanded)

        prioritized = [self._prioritize_path(path) for path in refined_paths]
        failures = self._failure_analysis(report, prioritized)

        return AttackPathReport(
            graph=graph,
            primitives=primitives,
            attack_paths=prioritized,
            refinement_rounds=refinement_rounds,
            failure_analysis=failures,
        )

    def _assert_required_input(self, report: IntelligenceReport) -> None:
        if not report.endpoints:
            raise ValueError("endpoints missing for attack path generation")
        if not report.classifications:
            raise ValueError("classified findings missing for attack path generation")
        if not report.parameter_profiles:
            raise ValueError("parameter profiles missing for attack path generation")

    def _build_graph(self, report: IntelligenceReport) -> AttackPathGraph:
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, str]] = []

        for endpoint in report.endpoints:
            node_id = f"endpoint:{endpoint}"
            nodes[node_id] = {"type": "endpoint", "value": endpoint}
            for param, _ in parse_qsl(urlparse(endpoint).query, keep_blank_values=True):
                p_node = f"parameter:{param}"
                nodes.setdefault(p_node, {"type": "parameter", "value": param})
                edges.append({"from": p_node, "to": node_id, "type": "param_to_endpoint"})

        for finding in report.classifications:
            f_node = f"finding:{finding.type}:{finding.endpoint}:{finding.parameter}"
            nodes[f_node] = {
                "type": "finding",
                "value": finding.type,
                "confidence": finding.confidence,
                "endpoint": finding.endpoint,
                "parameter": finding.parameter,
            }
            edges.append({"from": f"endpoint:{finding.endpoint}", "to": f_node, "type": "endpoint_to_finding"})
            p_node = f"parameter:{finding.parameter}"
            nodes.setdefault(p_node, {"type": "parameter", "value": finding.parameter})
            edges.append({"from": p_node, "to": f_node, "type": "parameter_to_finding"})

        for rel in report.relationships:
            cluster_node = f"cluster:{rel.cluster}"
            nodes[cluster_node] = {"type": "cluster", "value": rel.cluster, "risk": rel.risk}
            for endpoint in rel.endpoints:
                endpoint_node = f"endpoint:{endpoint}"
                nodes.setdefault(endpoint_node, {"type": "endpoint", "value": endpoint})
                edges.append({"from": cluster_node, "to": endpoint_node, "type": "cluster_to_endpoint"})

        return AttackPathGraph(nodes=nodes, edges=edges)

    def _build_primitives(self, findings: list[VulnerabilityClassification]) -> list[AttackPrimitive]:
        primitive_map = {
            "IDOR_candidate": AttackPrimitive(
                type="IDOR_candidate",
                capability="horizontal data access",
                preconditions=["identifier parameter", "authenticated context or bypass"],
                impact="data exposure",
            ),
            "auth_bypass_candidate": AttackPrimitive(
                type="auth_bypass_candidate",
                capability="unauthorized access",
                preconditions=["auth context manipulation"],
                impact="access control bypass",
            ),
            "reflection_detected": AttackPrimitive(
                type="reflection_detected",
                capability="input injection vector",
                preconditions=["reflected unsanitized input"],
                impact="client-side execution risk",
            ),
            "enumeration_vector": AttackPrimitive(
                type="enumeration_vector",
                capability="information discovery",
                preconditions=["behavioral response variation"],
                impact="resource enumeration",
            ),
        }

        used = sorted({f.type for f in findings})
        return [primitive_map[t] for t in used if t in primitive_map]

    def _generate_candidate_paths(self, report: IntelligenceReport) -> list[AttackPath]:
        findings_by_endpoint: dict[str, list[PrioritizedFinding | VulnerabilityClassification]] = defaultdict(list)
        for finding in report.classifications:
            findings_by_endpoint[finding.endpoint].append(finding)

        paths: list[AttackPath] = []
        path_counter = 1

        for rel in report.relationships:
            if len(rel.endpoints) < 2:
                continue
            for src_idx in range(len(rel.endpoints) - 1):
                src = rel.endpoints[src_idx]
                dst = rel.endpoints[src_idx + 1]
                for src_finding in findings_by_endpoint.get(src, []):
                    for dst_finding in findings_by_endpoint.get(dst, []):
                        if not self._compatible_findings(src_finding, dst_finding, rel):
                            continue
                        steps = self._build_steps(src_finding, dst_finding, rel)
                        impact = self._path_impact(src_finding.type, dst_finding.type)
                        confidence = round((src_finding.confidence + dst_finding.confidence) / 2, 3)
                        paths.append(
                            AttackPath(
                                path_id=f"AP-{path_counter:03d}",
                                steps=steps,
                                primitive_types=[src_finding.type, dst_finding.type],
                                impact=impact,
                                confidence=confidence,
                                status="unreachable",  # not yet replayed; _validate_paths sets the real status
                                validated=False,
                                evidence=[],
                                priority="unknown",
                                score=0.0,
                            )
                        )
                        path_counter += 1
        return paths

    def _compatible_findings(
        self,
        left: VulnerabilityClassification,
        right: VulnerabilityClassification,
        relationship: CorrelationRelationship,
    ) -> bool:
        if left.endpoint == right.endpoint:
            return False
        if left.parameter != right.parameter and relationship.cluster not in {
            "id", "user_identifier", "token", "auth", "role",
        }:
            return False
        if left.type == "reflection_detected" and right.type == "reflection_detected":
            return False
        return True

    def _build_steps(
        self,
        left: VulnerabilityClassification,
        right: VulnerabilityClassification,
        relationship: CorrelationRelationship,
    ) -> list[AttackPathStep]:
        return [
            AttackPathStep(
                step_id="S1",
                endpoint=left.endpoint,
                method=left.method,
                parameter=left.parameter,
                action=f"exploit_{left.type}",
                expected_outcome="obtain pivotable identifier/data",
                finding_type=left.type,
            ),
            AttackPathStep(
                step_id="S2",
                endpoint=right.endpoint,
                method=right.method,
                parameter=right.parameter,
                action=f"pivot_via_cluster_{relationship.cluster}",
                expected_outcome="access related downstream resource",
                finding_type="",  # transitional step, not itself a finding to re-confirm
            ),
            AttackPathStep(
                step_id="S3",
                endpoint=right.endpoint,
                method=right.method,
                parameter=right.parameter,
                action=f"confirm_{right.type}",
                expected_outcome="confirm chained impact",
                finding_type=right.type,
            ),
        ]

    def _validate_paths(self, paths: list[AttackPath]) -> list[AttackPath]:
        """Replay each path's steps and classify the result honestly.

        A step's HTTP request completing (any status) only proves the
        endpoint is reachable — it says nothing about whether the
        hypothesized vulnerability actually chains. Reachability and
        corroboration are tracked separately so a 404/403 on replay can't
        be mistaken for a successful exploit chain (the bug this replaces:
        `reliability = 1.0 if path.validated else 0.0` was previously set
        from "did every request avoid erroring," not from the requests
        actually reproducing each step's expected outcome).
        """
        results: list[AttackPath] = []
        for path in paths:
            evidence: list[dict[str, Any]] = []
            reachable = True
            corroborated = True
            for step in path.steps:
                test_url = self._mutate_step_url(step.endpoint, step.parameter)
                observation = self.collector.collect_request(
                    test_url,
                    arguments={"method": step.method},
                )
                step_ok = _step_corroborated(step.finding_type, observation.response_status)
                step.evidence = {
                    "target_url": test_url,
                    "status": observation.response_status,
                    "length": observation.response_length,
                    "evidence_id": observation.evidence_id,
                    "corroborated": step_ok,
                }
                evidence.append(step.evidence)
                if observation.response_status == 0:
                    reachable = False
                    corroborated = False
                    break
                if not step_ok:
                    corroborated = False

            path.status = "corroborated" if corroborated else ("reachable" if reachable else "unreachable")
            path.validated = path.status == "corroborated"
            path.evidence = evidence
            if reachable:
                results.append(path)
        return results

    @staticmethod
    def _mutate_step_url(endpoint: str, parameter: str) -> str:
        parsed = urlparse(endpoint)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if parameter:
            params[parameter] = params.get(parameter, "1") or "1"
            if params[parameter].isdigit():
                params[parameter] = "999"
            else:
                params[parameter] = "mutated"
        mutated_query = urlencode(sorted(params.items()), doseq=True)
        return urlunparse(parsed._replace(query=mutated_query))

    def _refine_paths(self, report: IntelligenceReport, paths: list[AttackPath]) -> list[AttackPath]:
        refined: list[AttackPath] = []
        by_endpoint: dict[str, list[VulnerabilityClassification]] = defaultdict(list)
        for finding in report.classifications:
            by_endpoint[finding.endpoint].append(finding)

        counter = 1
        for base in paths:
            last_endpoint = base.steps[-1].endpoint
            existing_steps = {
                (step.endpoint, step.parameter, step.finding_type) for step in base.steps
            }
            for next_finding in by_endpoint.get(last_endpoint, []):
                if (next_finding.endpoint, next_finding.parameter, next_finding.type) in existing_steps:
                    continue
                extra_step = AttackPathStep(
                    step_id="S4",
                    endpoint=next_finding.endpoint,
                    method=next_finding.method,
                    parameter=next_finding.parameter,
                    action=f"expand_{next_finding.type}",
                    expected_outcome="deepen exploitation path",
                    finding_type=next_finding.type,
                )
                refined.append(
                    AttackPath(
                        path_id=f"{base.path_id}-R{counter}",
                        steps=[*base.steps, extra_step],
                        primitive_types=[*base.primitive_types, next_finding.type],
                        impact=base.impact,
                        confidence=min(1.0, round(base.confidence + 0.05, 3)),
                        status="unreachable",  # not yet replayed; _validate_paths sets the real status
                        validated=False,
                        evidence=[],
                        priority="unknown",
                        score=0.0,
                    )
                )
                counter += 1
        return refined or paths

    def _prioritize_path(self, path: AttackPath) -> AttackPath:
        impact_weight = {"privilege escalation": 4.0, "data exposure": 3.5, "access control bypass": 3.8}.get(path.impact, 2.5)
        exploitability = max(1.0, 4.0 - (len(path.steps) * 0.5))
        # Graduated, not binary: a chain that replayed but didn't match its
        # expected outcome ("reachable") is not equivalent evidence to one
        # that did ("corroborated") — the old `1.0 if validated else 0.0`
        # conflated "the HTTP request didn't error" with "the vulnerability
        # chain was confirmed," letting a merely-reachable path reach the
        # same score as a corroborated one.
        reliability = {"corroborated": 1.0, "reachable": 0.4, "unreachable": 0.0}.get(path.status, 0.0)
        score = round((impact_weight * path.confidence * exploitability * reliability), 2)

        if score >= 9:
            priority = "critical"
        elif score >= 7:
            priority = "high"
        elif score >= 4:
            priority = "medium"
        else:
            priority = "low"

        path.score = score
        path.priority = priority
        return path

    @staticmethod
    def _path_impact(left_type: str, right_type: str) -> str:
        if "auth_bypass_candidate" in {left_type, right_type}:
            return "access control bypass"
        if "IDOR_candidate" in {left_type, right_type}:
            return "data exposure"
        return "privilege escalation"

    def _failure_analysis(self, report: IntelligenceReport, paths: list[AttackPath]) -> list[str]:
        failures: list[str] = []
        if paths:
            return failures

        if not report.relationships:
            failures.append("no_relationships: insufficient cross-endpoint correlation edges")
        if len(report.classifications) < 2:
            failures.append("insufficient_findings: not enough classified findings to chain")
        if all(f.type == "reflection_detected" for f in report.classifications):
            failures.append("weak_classification_diversity: findings do not provide pivot capabilities")
        if not report.mutations:
            failures.append("missing_mutation_coverage: no mutation intelligence available")
        return failures


# ---------- module-level helpers ----------

def _step_corroborated(finding_type: str, status: int) -> bool:
    """Does a replayed step's response status match what that finding type
    itself uses as its success signal (see reconforge/intelligence/engine.py
    ::_classify for the matching gates), rather than merely "some response
    came back"?

    - IDOR_candidate / auth_bypass_candidate: their own classification gate
      requires status == 200; corroboration on replay requires the same.
    - enumeration_vector: its classification gate is status >= 400 (or
      error wording) — a 200 on replay would actually *contradict* it.
    - "" (transitional pivot step, e.g. S2 in _build_steps): pivot steps
      describe traversal ("reach the next resource"), not a vulnerability
      signal to reconfirm — the destination endpoint may itself be an
      enumeration_vector target expecting an error status, so a pivot
      step must not impose its own status expectation on top of that.
      Reachability (status != 0) is already enforced separately in
      _validate_paths; this only decides whether the step counts toward
      *corroboration*, so it always does.
    - reflection_detected / any other/unknown type: no finding-specific
      status signal exists to re-check either, same reasoning as above.
    """
    if finding_type in {"IDOR_candidate", "auth_bypass_candidate"}:
        return status == 200
    if finding_type == "enumeration_vector":
        return status >= 400
    return True
