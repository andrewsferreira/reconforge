import sys
import types
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

if "reconforge" not in sys.modules:
    pkg = types.ModuleType("reconforge")
    pkg.__path__ = [str(PROJECT_ROOT / "reconforge")]
    sys.modules["reconforge"] = pkg
for subpkg in ["normalizers", "collectors", "entrypoints", "intelligence", "attack_paths"]:
    key = f"reconforge.{subpkg}"
    if key not in sys.modules:
        pkg = types.ModuleType(key)
        pkg.__path__ = [str(PROJECT_ROOT / "reconforge" / subpkg)]
        sys.modules[key] = pkg

for module_name, module_path in [
    ("reconforge.normalizers.http", PROJECT_ROOT / "reconforge" / "normalizers" / "http.py"),
    ("reconforge.collectors.http_collector", PROJECT_ROOT / "reconforge" / "collectors" / "http_collector.py"),
    ("reconforge.entrypoints.burp_web_validation", PROJECT_ROOT / "reconforge" / "entrypoints" / "burp_web_validation.py"),
    ("reconforge.intelligence.engine", PROJECT_ROOT / "reconforge" / "intelligence" / "engine.py"),
    ("reconforge.attack_paths.engine", PROJECT_ROOT / "reconforge" / "attack_paths" / "engine.py"),
]:
    spec = spec_from_file_location(module_name, module_path)
    assert spec and spec.loader
    mod = module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)

normalizer_mod = sys.modules["reconforge.normalizers.http"]
intel_mod = sys.modules["reconforge.intelligence.engine"]
attack_mod = sys.modules["reconforge.attack_paths.engine"]

HTTPObservation = normalizer_mod.HTTPObservation
IntelligenceReport = intel_mod.IntelligenceReport
VulnerabilityClassification = intel_mod.VulnerabilityClassification
ParameterProfile = intel_mod.ParameterProfile
CorrelationRelationship = intel_mod.CorrelationRelationship
AttackPathGenerationEngine = attack_mod.AttackPathGenerationEngine


class _CollectorStub:
    """Returns a status matching each endpoint's finding-type success
    signal (200 for the IDOR endpoint, 404 for the enumeration endpoint,
    per reconforge/attack_paths/engine.py::_step_corroborated), so replay
    genuinely corroborates the hypothesized chain rather than the test
    fixture accidentally contradicting its own findings."""

    def collect_request(self, url, arguments=None, http_version="http1"):
        status = 404 if "/api/order" in url else 200
        return HTTPObservation(
            target_url=url,
            scheme="https",
            host="target.local",
            method="GET",
            path=url.split("?", 1)[0],
            query=url.split("?", 1)[1] if "?" in url else "",
            request_headers={},
            request_body="",
            response_status=status,
            response_length=123,
            response_body="ok",
            response_headers={},
            source_tool="send_http1_request",
            source_provider="burp_mcp",
            evidence_id="ev-1",
        )


class _AlwaysOkCollectorStub:
    """Always returns 200 — realistic for an IDOR-only chain, but wrong for
    an enumeration_vector step (which expects an error/denial status), so
    it exercises the "reachable but not corroborated" path."""

    def collect_request(self, url, arguments=None, http_version="http1"):
        return HTTPObservation(
            target_url=url, scheme="https", host="target.local", method="GET",
            path=url.split("?", 1)[0], query=url.split("?", 1)[1] if "?" in url else "",
            request_headers={}, request_body="", response_status=200,
            response_length=123, response_body="ok", response_headers={},
            source_tool="send_http1_request", source_provider="burp_mcp", evidence_id="ev-1",
        )


def _report() -> IntelligenceReport:
    return IntelligenceReport(
        endpoints=[
            "https://target.local/api/user?user_id=1",
            "https://target.local/api/order?user_id=1",
        ],
        mutations=[],
        classifications=[
            VulnerabilityClassification(
                type="IDOR_candidate",
                confidence=0.9,
                evidence=["status_delta=200->200"],
                endpoint="https://target.local/api/user?user_id=1",
                method="GET",
                parameter="user_id",
            ),
            VulnerabilityClassification(
                type="enumeration_vector",
                confidence=0.7,
                evidence=["length_delta=40"],
                endpoint="https://target.local/api/order?user_id=1",
                method="GET",
                parameter="user_id",
            ),
        ],
        parameter_profiles=[
            ParameterProfile(
                canonical_name="user_identifier",
                raw_names=["user_id"],
                endpoints=[
                    "https://target.local/api/user?user_id=1",
                    "https://target.local/api/order?user_id=1",
                ],
                high_risk=True,
                risk_reason="identifier_parameter",
            )
        ],
        relationships=[
            CorrelationRelationship(
                cluster="user_identifier",
                endpoints=[
                    "https://target.local/api/user?user_id=1",
                    "https://target.local/api/order?user_id=1",
                ],
                risk="potential lateral access",
            )
        ],
        prioritized_findings=[],
    )


def test_attack_path_generation_produces_validated_paths():
    engine = AttackPathGenerationEngine(_CollectorStub())
    report = engine.run(_report(), refinement_rounds=1)

    assert report.graph.nodes
    assert report.primitives
    assert report.attack_paths
    assert report.attack_paths[0].status == "corroborated"
    assert report.attack_paths[0].validated is True
    assert report.attack_paths[0].evidence
    assert all(step_evidence["corroborated"] for step_evidence in report.attack_paths[0].evidence)
    assert report.attack_paths[0].priority in {"critical", "high", "medium", "low"}


def test_reachable_but_uncorroborated_path_is_labeled_honestly_and_scores_lower():
    """A path where every request completes (no errors) but the responses
    don't match what the chained findings actually predict must not be
    reported as equivalent to a corroborated one — this is the exact bug
    docs/ARCHITECTURE_REVIEW.md flagged: 'validated=True'/'priority=critical'
    could previously be produced from nothing more than a non-erroring
    HTTP response."""
    corroborated_engine = AttackPathGenerationEngine(_CollectorStub())
    corroborated_report = corroborated_engine.run(_report(), refinement_rounds=0)
    corroborated_path = corroborated_report.attack_paths[0]

    uncorroborated_engine = AttackPathGenerationEngine(_AlwaysOkCollectorStub())
    uncorroborated_report = uncorroborated_engine.run(_report(), refinement_rounds=0)
    uncorroborated_path = uncorroborated_report.attack_paths[0]

    assert corroborated_path.status == "corroborated"
    assert corroborated_path.validated is True

    assert uncorroborated_path.status == "reachable"
    assert uncorroborated_path.validated is False
    # every request still completed, so the path is kept (not dropped like
    # an unreachable one), just honestly labeled and scored lower
    assert uncorroborated_path.evidence

    assert uncorroborated_path.score < corroborated_path.score
    assert uncorroborated_path.priority != "critical"


def test_failure_analysis_when_no_relationships():
    engine = AttackPathGenerationEngine(_CollectorStub())
    data = _report()
    data.relationships = []

    report = engine.run(data, refinement_rounds=0)

    assert report.attack_paths == []
    assert report.failure_analysis
