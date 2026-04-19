"""Deterministic vulnerability classification and correlation engine."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
import json
import logging
from typing import Any
from urllib.parse import parse_qsl, urlparse

from reconforge.collectors.http_collector import HttpCollector
from reconforge.entrypoints.burp_web_validation import HttpMutationEngine
from reconforge.normalizers.http import HTTPObservation

LOGGER = logging.getLogger(__name__)

_IDENTIFIER_PARAMS = {"id", "uid", "user_id", "userid", "account_id", "owner_id"}
_AUTH_PARAMS = {"token", "auth", "authorization", "session", "jwt", "api_key"}
_ROLE_PARAMS = {"role", "is_admin", "permission", "scope"}


@dataclass
class ResponseMetrics:
    status_code: int
    response_length: int
    response_signature: str
    key_indicators: list[str]


@dataclass
class DifferenceIntelligence:
    status_delta: str
    length_delta_absolute: int
    length_delta_relative: float
    content_delta: bool
    behavior_flag: str


@dataclass
class MutationIntelligence:
    mutation_id: str
    parameter: str
    mutation_type: str
    mutated_value: str
    original_response: ResponseMetrics
    mutated_response: ResponseMetrics
    diff: DifferenceIntelligence


@dataclass
class VulnerabilityClassification:
    type: str
    confidence: float
    evidence: list[str]
    endpoint: str
    method: str
    parameter: str


@dataclass
class ParameterProfile:
    canonical_name: str
    raw_names: list[str]
    endpoints: list[str]
    high_risk: bool
    risk_reason: str


@dataclass
class CorrelationRelationship:
    cluster: str
    endpoints: list[str]
    risk: str


@dataclass
class PrioritizedFinding:
    finding: VulnerabilityClassification
    impact: str
    exploitability: str
    consistency: str
    exposure: str
    priority: str
    score: float


@dataclass
class IntelligenceReport:
    endpoints: list[str]
    mutations: list[MutationIntelligence]
    classifications: list[VulnerabilityClassification]
    parameter_profiles: list[ParameterProfile]
    relationships: list[CorrelationRelationship]
    prioritized_findings: list[PrioritizedFinding]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationLoopResult:
    baseline: IntelligenceReport
    correlated: IntelligenceReport
    improvement: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class VulnerabilityIntelligenceEngine:
    def __init__(self, collector: HttpCollector):
        self.collector = collector
        self.mutator = HttpMutationEngine()

    def run(self, endpoints: list[str], *, correlation_enabled: bool = True) -> IntelligenceReport:
        mutations: list[MutationIntelligence] = []
        classifications: list[VulnerabilityClassification] = []
        endpoint_param_map: dict[str, list[str]] = defaultdict(list)

        for endpoint in endpoints:
            baseline = self.collector.collect_request(endpoint)
            baseline_metrics = self._metrics_from_observation(baseline)
            query_pairs = parse_qsl(urlparse(endpoint).query, keep_blank_values=True)
            endpoint_param_map[endpoint].extend([name for name, _ in query_pairs])

            cases = self.mutator.build_cases(baseline, extended=True)
            LOGGER.info(json.dumps({"event": "vuln_engine_mutation_cases", "endpoint": endpoint, "count": len(cases)}))

            for case in cases:
                mutated = self.collector.collect_request(
                    case.mutated_url,
                    arguments={
                        "method": baseline.method,
                        "headers": baseline.request_headers,
                        "body": case.mutated_body,
                    },
                )
                mutated_metrics = self._metrics_from_observation(mutated)
                diff = self._difference(baseline_metrics, mutated_metrics)
                mutated_value = self._extract_mutated_value(case.mutated_url, case.mutated_body, case.param)
                mutation_record = MutationIntelligence(
                    mutation_id=case.mutation_id,
                    parameter=case.param,
                    mutation_type=case.mutation_type,
                    mutated_value=mutated_value,
                    original_response=baseline_metrics,
                    mutated_response=mutated_metrics,
                    diff=diff,
                )
                mutations.append(mutation_record)
                endpoint_param_map[endpoint].append(case.param)

                classifications.extend(
                    self._classify(
                        endpoint=endpoint,
                        method=baseline.method,
                        parameter=case.param,
                        mutated_value=mutated_value,
                        baseline=baseline,
                        mutated=mutated,
                        diff=diff,
                    )
                )

        parameter_profiles = self._build_parameter_profiles(endpoint_param_map)
        relationships = self._correlate_profiles(parameter_profiles) if correlation_enabled else []
        if correlation_enabled and relationships:
            classifications = self._apply_correlation_boost(classifications, relationships)
        prioritized = self._prioritize(classifications)

        return IntelligenceReport(
            endpoints=endpoints,
            mutations=mutations,
            classifications=classifications,
            parameter_profiles=parameter_profiles,
            relationships=relationships,
            prioritized_findings=prioritized,
        )

    def run_validation_loop(self, endpoints: list[str]) -> ValidationLoopResult:
        baseline = self.run(endpoints, correlation_enabled=False)
        correlated = self.run(endpoints, correlation_enabled=True)

        baseline_count = len(baseline.prioritized_findings)
        correlated_count = len(correlated.prioritized_findings)
        baseline_avg = _avg([f.score for f in baseline.prioritized_findings])
        correlated_avg = _avg([f.score for f in correlated.prioritized_findings])

        improvement = {
            "baseline_findings": baseline_count,
            "correlated_findings": correlated_count,
            "baseline_avg_score": baseline_avg,
            "correlated_avg_score": correlated_avg,
            "improved": (correlated_count > baseline_count) or (correlated_avg > baseline_avg),
        }
        return ValidationLoopResult(baseline=baseline, correlated=correlated, improvement=improvement)

    def _metrics_from_observation(self, observation: HTTPObservation) -> ResponseMetrics:
        signature = f"{observation.response_status}:{observation.response_length}:{hash(observation.response_body)}"
        indicators = [kw for kw in ("error", "unauthorized", "forbidden", "invalid", "exception") if kw in observation.response_body.lower()]
        return ResponseMetrics(
            status_code=observation.response_status,
            response_length=observation.response_length,
            response_signature=signature,
            key_indicators=indicators,
        )

    def _difference(self, original: ResponseMetrics, mutated: ResponseMetrics) -> DifferenceIntelligence:
        status_delta = f"{original.status_code}->{mutated.status_code}"
        length_abs = abs(mutated.response_length - original.response_length)
        length_rel = round((length_abs / original.response_length), 4) if original.response_length else 1.0
        content_delta = original.response_signature != mutated.response_signature

        if not content_delta and length_abs == 0 and original.status_code == mutated.status_code:
            flag = "identical"
        elif mutated.status_code == original.status_code and length_rel < 0.2:
            flag = "minor_variation"
        else:
            flag = "significant_variation"

        return DifferenceIntelligence(
            status_delta=status_delta,
            length_delta_absolute=length_abs,
            length_delta_relative=length_rel,
            content_delta=content_delta,
            behavior_flag=flag,
        )

    def _classify(
        self,
        *,
        endpoint: str,
        method: str,
        parameter: str,
        mutated_value: str,
        baseline: HTTPObservation,
        mutated: HTTPObservation,
        diff: DifferenceIntelligence,
    ) -> list[VulnerabilityClassification]:
        findings: list[VulnerabilityClassification] = []
        param_norm = _canonical_param(parameter)

        if param_norm in {"id", "user_identifier"} and diff.behavior_flag == "significant_variation" and mutated.response_status == 200:
            findings.append(
                VulnerabilityClassification(
                    type="IDOR_candidate",
                    confidence=0.85,
                    evidence=[
                        f"parameter={parameter}",
                        f"status_delta={diff.status_delta}",
                        f"length_delta={diff.length_delta_absolute}",
                    ],
                    endpoint=endpoint,
                    method=method,
                    parameter=parameter,
                )
            )

        if param_norm in {"auth", "token"} and mutated.response_status == 200:
            findings.append(
                VulnerabilityClassification(
                    type="auth_bypass_candidate",
                    confidence=0.8,
                    evidence=[f"parameter={parameter}", f"mutated_value={mutated_value}", f"status={mutated.response_status}"],
                    endpoint=endpoint,
                    method=method,
                    parameter=parameter,
                )
            )

        if mutated_value and mutated_value in (mutated.response_body or ""):
            findings.append(
                VulnerabilityClassification(
                    type="reflection_detected",
                    confidence=0.6,
                    evidence=[f"reflected_value={mutated_value}", f"parameter={parameter}"],
                    endpoint=endpoint,
                    method=method,
                    parameter=parameter,
                )
            )

        if diff.behavior_flag == "significant_variation" and (
            "error" in mutated.response_body.lower() or "invalid" in mutated.response_body.lower() or mutated.response_status >= 400
        ):
            findings.append(
                VulnerabilityClassification(
                    type="enumeration_vector",
                    confidence=0.7,
                    evidence=[f"status_delta={diff.status_delta}", f"behavior={diff.behavior_flag}"],
                    endpoint=endpoint,
                    method=method,
                    parameter=parameter,
                )
            )

        return findings

    def _build_parameter_profiles(self, endpoint_param_map: dict[str, list[str]]) -> list[ParameterProfile]:
        grouped: dict[str, set[str]] = defaultdict(set)
        grouped_endpoints: dict[str, set[str]] = defaultdict(set)

        for endpoint, params in endpoint_param_map.items():
            for param in params:
                canonical = _canonical_param(param)
                grouped[canonical].add(param)
                grouped_endpoints[canonical].add(endpoint)

        profiles: list[ParameterProfile] = []
        for canonical, raw_names in grouped.items():
            high_risk, reason = _param_risk(canonical)
            profiles.append(
                ParameterProfile(
                    canonical_name=canonical,
                    raw_names=sorted(raw_names),
                    endpoints=sorted(grouped_endpoints[canonical]),
                    high_risk=high_risk,
                    risk_reason=reason,
                )
            )
        return sorted(profiles, key=lambda p: p.canonical_name)

    def _correlate_profiles(self, profiles: list[ParameterProfile]) -> list[CorrelationRelationship]:
        relationships: list[CorrelationRelationship] = []
        for profile in profiles:
            if len(profile.endpoints) < 2:
                continue
            risk = "potential lateral access" if profile.high_risk else "parameter reuse"
            relationships.append(
                CorrelationRelationship(
                    cluster=profile.canonical_name,
                    endpoints=profile.endpoints,
                    risk=risk,
                )
            )
        return relationships

    def _prioritize(self, findings: list[VulnerabilityClassification]) -> list[PrioritizedFinding]:
        prioritized: list[PrioritizedFinding] = []
        for finding in findings:
            impact, exposure, exploitability = _priority_traits(finding.type)
            consistency = "repeatable" if finding.confidence >= 0.75 else "moderate"
            score = round(finding.confidence * _impact_weight(impact) * _exploit_weight(exploitability), 3)
            priority = _score_to_priority(score)
            prioritized.append(
                PrioritizedFinding(
                    finding=finding,
                    impact=impact,
                    exploitability=exploitability,
                    consistency=consistency,
                    exposure=exposure,
                    priority=priority,
                    score=score,
                )
            )
        prioritized.sort(key=lambda item: item.score, reverse=True)
        return prioritized


    def _apply_correlation_boost(
        self,
        classifications: list[VulnerabilityClassification],
        relationships: list[CorrelationRelationship],
    ) -> list[VulnerabilityClassification]:
        boosted_clusters = {rel.cluster for rel in relationships}
        boosted: list[VulnerabilityClassification] = []
        for finding in classifications:
            cluster = _canonical_param(finding.parameter)
            confidence = finding.confidence
            evidence = list(finding.evidence)
            if cluster in boosted_clusters:
                confidence = min(1.0, round(confidence + 0.1, 3))
                evidence.append(f"correlated_cluster={cluster}")
            boosted.append(
                VulnerabilityClassification(
                    type=finding.type,
                    confidence=confidence,
                    evidence=evidence,
                    endpoint=finding.endpoint,
                    method=finding.method,
                    parameter=finding.parameter,
                )
            )
        return boosted

    @staticmethod
    def _extract_mutated_value(url: str, body: str, parameter: str) -> str:
        url_params = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        if parameter in url_params:
            return url_params[parameter]
        body_params = dict(parse_qsl(body, keep_blank_values=True))
        return body_params.get(parameter, "")


# ---------- helper functions ----------

def _canonical_param(name: str) -> str:
    cleaned = name.lower().strip().replace("-", "_")
    mapping = {
        "uid": "user_identifier",
        "user_id": "user_identifier",
        "userid": "user_identifier",
        "account_id": "user_identifier",
        "auth": "auth",
        "authorization": "auth",
        "jwt": "token",
        "api_key": "token",
    }
    if cleaned in mapping:
        return mapping[cleaned]
    if cleaned in _IDENTIFIER_PARAMS:
        return "id"
    if cleaned in _AUTH_PARAMS:
        return "token"
    if cleaned in _ROLE_PARAMS:
        return "role"
    return cleaned


def _param_risk(canonical: str) -> tuple[bool, str]:
    if canonical in {"id", "user_identifier"}:
        return True, "identifier_parameter"
    if canonical in {"token", "auth", "role"}:
        return True, "auth_or_role_parameter"
    return False, "standard_parameter"


def _priority_traits(finding_type: str) -> tuple[str, str, str]:
    if finding_type == "IDOR_candidate":
        return "high", "authenticated", "simple_parameter_change"
    if finding_type == "auth_bypass_candidate":
        return "high", "authenticated", "simple_parameter_change"
    if finding_type == "reflection_detected":
        return "medium", "public", "simple_parameter_change"
    if finding_type == "enumeration_vector":
        return "medium", "public", "simple_parameter_change"
    return "low", "unknown", "complex"


def _impact_weight(impact: str) -> float:
    return {"critical": 1.3, "high": 1.2, "medium": 1.0, "low": 0.8}.get(impact, 0.8)


def _exploit_weight(exploitability: str) -> float:
    return {"simple_parameter_change": 1.2, "moderate": 1.0, "complex": 0.8}.get(exploitability, 1.0)


def _score_to_priority(score: float) -> str:
    if score >= 1.0:
        return "critical"
    if score >= 0.85:
        return "high"
    if score >= 0.65:
        return "medium"
    return "low"


def _avg(values: list[float]) -> float:
    return round(sum(values) / len(values), 3) if values else 0.0
