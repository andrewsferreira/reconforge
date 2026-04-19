import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from core.adapters.burp.models import NormalizedBurpHttpRecord

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = PROJECT_ROOT / "reconforge" / "normalizers" / "http.py"
SPEC = spec_from_file_location("reconforge.normalizers.http", MODULE_PATH)
assert SPEC and SPEC.loader
http_module = module_from_spec(SPEC)
sys.modules["reconforge.normalizers.http"] = http_module
SPEC.loader.exec_module(http_module)

HttpObservationNormalizer = http_module.HttpObservationNormalizer


def test_normalizes_valid_record():
    normalizer = HttpObservationNormalizer()
    record = NormalizedBurpHttpRecord(
        url="https://example.com:8443/api/items?id=1",
        host="example.com",
        method="get",
        status_code=200,
        response_body_length=120,
        request_headers={"content-type": "application/json"},
        response_headers={"x-powered-by": "burp"},
    )

    observation = normalizer.normalize(record, source_tool="get_proxy_http_history", source_provider="burp_mcp")

    assert observation.target_url == "https://example.com:8443/api/items?id=1"
    assert observation.scheme == "https"
    assert observation.host == "example.com"
    assert observation.port == 8443
    assert observation.method == "GET"
    assert observation.path == "/api/items"
    assert observation.query == "id=1"
    assert observation.request_headers["Content-Type"] == "application/json"
    assert observation.response_headers["X-Powered-By"] == "burp"
    assert observation.response_status == 200
    assert observation.response_length == 120
    assert observation.evidence_id.startswith("burp_mcp:get_proxy_http_history:")


def test_normalizes_missing_fields_gracefully():
    normalizer = HttpObservationNormalizer()

    observation = normalizer.normalize(
        {"url": "https://example.com"},
        source_tool="send_http1_request",
        source_provider="burp_mcp",
    )

    assert observation.host == "example.com"
    assert observation.response_status == 0
    assert observation.request_headers == {}
    assert observation.response_headers == {}
    assert observation.timestamp
