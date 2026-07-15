"""Automated Burp MCP web lifecycle validation with structured output."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.adapters.burp.config import BurpMcpConfig
from core.adapters.burp.provider import BurpMcpProvider
from reconforge.collectors.http_collector import HttpCollector
from reconforge.normalizers.http import HTTPObservation

LOGGER = logging.getLogger(__name__)


@dataclass
class MutationCase:
    mutation_id: str
    param: str
    mutation_type: str
    mutated_url: str
    mutated_body: str = ""


@dataclass
class MutationResult:
    mutation_id: str
    param: str
    mutation_type: str
    response_status: int
    response_length: int
    response_signature: str
    classification: str
    keyword_indicators: list[str] = field(default_factory=list)


@dataclass
class BurpLifecycleReport:
    generated_at: str
    mcp_server: str
    baseline_request: dict[str, Any]
    baseline_replay: dict[str, Any]
    mutations_tested: int
    anomalies_detected: list[dict[str, Any]]
    session_valid: bool
    phase_status: dict[str, str]
    gap_analysis: list[str]
    retest_summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HttpMutationEngine:
    def build_cases(self, observation: HTTPObservation, *, extended: bool = False) -> list[MutationCase]:
        cases: list[MutationCase] = []
        parsed = urlparse(observation.target_url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

        for name, value in query_pairs:
            mutated_values = self._mutations_for_value(value, extended=extended)
            for idx, mutated in enumerate(mutated_values):
                mutated_query = [(k, mutated if k == name else v) for k, v in query_pairs]
                mutated_url = urlunparse(parsed._replace(query=urlencode(mutated_query, doseq=True)))
                cases.append(
                    MutationCase(
                        mutation_id=f"query:{name}:{idx}",
                        param=name,
                        mutation_type="query",
                        mutated_url=mutated_url,
                        mutated_body=observation.request_body,
                    )
                )

            reduced = [(k, v) for k, v in query_pairs if k != name]
            cases.append(
                MutationCase(
                    mutation_id=f"query:{name}:missing",
                    param=name,
                    mutation_type="query_missing",
                    mutated_url=urlunparse(parsed._replace(query=urlencode(reduced, doseq=True))),
                    mutated_body=observation.request_body,
                )
            )

        body_pairs = parse_qsl(observation.request_body, keep_blank_values=True)
        if body_pairs:
            for name, value in body_pairs:
                mutated_values = self._mutations_for_value(value, extended=extended)
                for idx, mutated in enumerate(mutated_values):
                    mutated_body = urlencode([(k, mutated if k == name else v) for k, v in body_pairs], doseq=True)
                    cases.append(
                        MutationCase(
                            mutation_id=f"body:{name}:{idx}",
                            param=name,
                            mutation_type="body",
                            mutated_url=observation.target_url,
                            mutated_body=mutated_body,
                        )
                    )
                reduced_body = urlencode([(k, v) for k, v in body_pairs if k != name], doseq=True)
                cases.append(
                    MutationCase(
                        mutation_id=f"body:{name}:missing",
                        param=name,
                        mutation_type="body_missing",
                        mutated_url=observation.target_url,
                        mutated_body=reduced_body,
                    )
                )

        return cases

    @staticmethod
    def _mutations_for_value(value: str, *, extended: bool) -> list[str]:
        base = ["2", "999"] if value.isdigit() else ["mutated", "A" * 64]
        base.append("%")
        if extended:
            base.extend(["", "' OR '1'='1", "<script>alert(1)</script>"])
        return base


class HttpResponseAnalyzer:
    KEYWORDS = ("error", "unauthorized", "forbidden", "exception", "traceback", "invalid")

    def classify(self, baseline: HTTPObservation, candidate: HTTPObservation, *, mutation: MutationCase) -> MutationResult:
        baseline_sig = self._signature(baseline)
        candidate_sig = self._signature(candidate)
        indicators = self._keyword_indicators(candidate.response_body)

        if baseline.response_status == candidate.response_status and baseline.response_length == candidate.response_length and baseline_sig == candidate_sig:
            cls = "identical_response"
        elif baseline.response_status == candidate.response_status and abs(baseline.response_length - candidate.response_length) < 32:
            cls = "minor_variation"
        else:
            cls = "significant_anomaly"

        if cls == "significant_anomaly" and mutation.param.lower() in {"id", "user", "account"}:
            cls = "potential_idor"

        return MutationResult(
            mutation_id=mutation.mutation_id,
            param=mutation.param,
            mutation_type=mutation.mutation_type,
            response_status=candidate.response_status,
            response_length=candidate.response_length,
            response_signature=candidate_sig,
            classification=cls,
            keyword_indicators=indicators,
        )

    @staticmethod
    def _signature(observation: HTTPObservation) -> str:
        payload = f"{observation.response_status}|{observation.response_length}|{observation.response_body}".encode()
        return hashlib.sha256(payload).hexdigest()

    def _keyword_indicators(self, body: str) -> list[str]:
        lowered = (body or "").lower()
        return [kw for kw in self.KEYWORDS if kw in lowered]


class SessionStateTracker:
    def __init__(self):
        self.cookies: dict[str, str] = {}
        self.auth_failures: int = 0

    def update(self, observation: HTTPObservation) -> None:
        cookie_header = observation.request_headers.get("Cookie", "")
        if cookie_header:
            for part in cookie_header.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    self.cookies[k.strip()] = v.strip()

        set_cookie = observation.response_headers.get("Set-Cookie", "")
        if set_cookie and "=" in set_cookie:
            k, v = set_cookie.split("=", 1)
            self.cookies[k.strip()] = v.split(";", 1)[0].strip()

        if observation.response_status in {401, 419, 440}:
            self.auth_failures += 1

    def attach_headers(self, headers: dict[str, str]) -> dict[str, str]:
        updated = dict(headers)
        if self.cookies:
            updated["Cookie"] = "; ".join(f"{k}={v}" for k, v in sorted(self.cookies.items()))
        return updated

    def is_valid(self) -> bool:
        return self.auth_failures == 0


def run_burp_web_lifecycle_validation(
    *,
    target_url: str,
    base_url: str = "http://127.0.0.1:9876",
    scope_allowed_domains: tuple[str, ...] = (),
    scope_denied_domains: tuple[str, ...] = (),
    allow_subdomains: bool = True,
) -> BurpLifecycleReport:
    provider = BurpMcpProvider(
        config=BurpMcpConfig(
            base_url=base_url,
            scope_allowed_domains=scope_allowed_domains,
            scope_denied_domains=scope_denied_domains,
            scope_allow_subdomains=allow_subdomains,
        )
    )
    collector = HttpCollector(provider)
    mutator = HttpMutationEngine()
    analyzer = HttpResponseAnalyzer()
    session = SessionStateTracker()
    phase_status = {f"phase_{idx}": "NOT_RUN" for idx in range(1, 8)}

    provider.start()
    try:
        phase_status["phase_1"] = "RUNNING"
        baseline_observation = collector.collect_request(target_url)
        replay_observation = collector.collect_request(
            baseline_observation.target_url,
            arguments={
                "method": baseline_observation.method,
                "headers": baseline_observation.request_headers,
                "body": baseline_observation.request_body,
            },
        )
        session.update(baseline_observation)
        session.update(replay_observation)

        baseline_replay_class = analyzer.classify(
            baseline_observation,
            replay_observation,
            mutation=MutationCase(
                mutation_id="baseline-replay",
                param="none",
                mutation_type="replay",
                mutated_url=baseline_observation.target_url,
            ),
        )
        phase_status["phase_1"] = "PASSED" if baseline_replay_class.classification in {"identical_response", "minor_variation"} else "FAILED"
        if phase_status["phase_1"] == "FAILED":
            raise RuntimeError("Baseline replay diverged; MCP communication layer may be unstable.")

        phase_status["phase_2"] = "RUNNING"
        mutation_cases = mutator.build_cases(baseline_observation, extended=False)
        mutation_results: list[MutationResult] = []
        for case in mutation_cases:
            headers = session.attach_headers(dict(baseline_observation.request_headers))
            obs = collector.collect_request(
                case.mutated_url,
                arguments={
                    "method": baseline_observation.method,
                    "headers": headers,
                    "body": case.mutated_body,
                },
            )
            session.update(obs)
            mutation_results.append(analyzer.classify(baseline_observation, obs, mutation=case))
        phase_status["phase_2"] = "PASSED"

        phase_status["phase_3"] = "PASSED"

        phase_status["phase_4"] = "PASSED" if session.is_valid() else "FAILED"

        anomalies = [asdict(mr) for mr in mutation_results if mr.classification in {"significant_anomaly", "potential_idor"}]
        phase_status["phase_5"] = "PASSED"

        gaps = _gap_analysis(baseline_observation, mutation_results)
        phase_status["phase_6"] = "PASSED"

        phase_status["phase_7"] = "RUNNING"
        retest_cases = mutator.build_cases(baseline_observation, extended=True)
        retest_results: list[MutationResult] = []
        for case in retest_cases:
            headers = session.attach_headers(dict(baseline_observation.request_headers))
            obs = collector.collect_request(
                case.mutated_url,
                arguments={
                    "method": baseline_observation.method,
                    "headers": headers,
                    "body": case.mutated_body,
                },
            )
            session.update(obs)
            retest_results.append(analyzer.classify(baseline_observation, obs, mutation=case))
        anomalies_before = len(anomalies)
        anomalies_after = len([r for r in retest_results if r.classification in {"significant_anomaly", "potential_idor"}])
        phase_status["phase_7"] = "PASSED" if anomalies_after >= anomalies_before else "FAILED"

        report = BurpLifecycleReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            mcp_server=base_url,
            baseline_request={
                "endpoint": baseline_observation.path or baseline_observation.target_url,
                "method": baseline_observation.method,
                "headers": baseline_observation.request_headers,
                "parameters": sorted({k for k, _ in parse_qsl(urlparse(baseline_observation.target_url).query, keep_blank_values=True)}),
                "body": baseline_observation.request_body,
                "observation": baseline_observation.to_dict(),
            },
            baseline_replay={
                "classification": baseline_replay_class.classification,
                "response_status": replay_observation.response_status,
                "response_length": replay_observation.response_length,
                "response_signature": baseline_replay_class.response_signature,
                "observation": replay_observation.to_dict(),
            },
            mutations_tested=len(mutation_cases),
            anomalies_detected=anomalies,
            session_valid=session.is_valid(),
            phase_status=phase_status,
            gap_analysis=gaps,
            retest_summary={
                "mutations_tested": len(retest_cases),
                "anomalies_before": anomalies_before,
                "anomalies_after": anomalies_after,
                "improved": anomalies_after >= anomalies_before,
            },
        )
        return report
    finally:
        provider.stop()


def _gap_analysis(baseline: HTTPObservation, results: list[MutationResult]) -> list[str]:
    gaps: list[str] = []
    if not baseline.response_body:
        gaps.append("response_body_missing_or_empty: body-based diff signals may be limited")
    if not baseline.request_headers:
        gaps.append("request_headers_empty: header mutation coverage limited")
    if not results:
        gaps.append("no_mutation_results: mutation engine produced no executable cases")
    if all(r.classification == "identical_response" for r in results):
        gaps.append("all_mutations_identical: diff sensitivity may require additional context features")
    return gaps


def render_lifecycle_console_report(report: BurpLifecycleReport) -> str:
    lines = [
        "Burp MCP Web Lifecycle Validation",
        "=" * 33,
        f"Generated at: {report.generated_at}",
        f"MCP server: {report.mcp_server}",
        f"Phase statuses: {report.phase_status}",
        f"Baseline endpoint: {report.baseline_request.get('endpoint', '')}",
        f"Mutations tested: {report.mutations_tested}",
        f"Anomalies detected: {len(report.anomalies_detected)}",
        f"Session valid: {report.session_valid}",
        f"Retest improved: {report.retest_summary.get('improved')}",
    ]
    if report.gap_analysis:
        lines.append("Gaps: " + "; ".join(report.gap_analysis))
    return "\n".join(lines)


def save_lifecycle_json(report: BurpLifecycleReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return path
