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
if "reconforge.normalizers" not in sys.modules:
    pkg = types.ModuleType("reconforge.normalizers")
    pkg.__path__ = [str(PROJECT_ROOT / "reconforge" / "normalizers")]
    sys.modules["reconforge.normalizers"] = pkg
if "reconforge.collectors" not in sys.modules:
    pkg = types.ModuleType("reconforge.collectors")
    pkg.__path__ = [str(PROJECT_ROOT / "reconforge" / "collectors")]
    sys.modules["reconforge.collectors"] = pkg

# preload dependencies used by the entrypoint module
for module_name, module_path in [
    ("reconforge.normalizers.http", PROJECT_ROOT / "reconforge" / "normalizers" / "http.py"),
    ("reconforge.collectors.http_collector", PROJECT_ROOT / "reconforge" / "collectors" / "http_collector.py"),
]:
    spec = spec_from_file_location(module_name, module_path)
    assert spec and spec.loader
    mod = module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)

ENTRYPOINT_PATH = PROJECT_ROOT / "reconforge" / "entrypoints" / "burp_web_validation.py"
SPEC = spec_from_file_location("_burp_web_validation", ENTRYPOINT_PATH)
assert SPEC and SPEC.loader
burp_web_validation = module_from_spec(SPEC)
sys.modules["_burp_web_validation"] = burp_web_validation
SPEC.loader.exec_module(burp_web_validation)

run_burp_web_lifecycle_validation = burp_web_validation.run_burp_web_lifecycle_validation


class _ProviderStub:
    def __init__(self, config):
        self.config = config

    def start(self):
        return None

    def stop(self):
        return None

    def send_http1_request(self, arguments):
        url = arguments.get("url", "")
        status = 200
        body = "ok"
        if "999" in url:
            body = "error unauthorized"
            status = 403
        return [{"url": url, "host": "example.com", "method": "GET", "status_code": status, "response_body_length": len(body), "response_body": body, "request_headers": arguments.get("headers", {}), "request_body": arguments.get("body", ""), "response_headers": {"Set-Cookie": "sid=abc; Path=/"}}]

    def send_http2_request(self, arguments):
        return self.send_http1_request(arguments)


def test_lifecycle_validation_produces_structured_report(monkeypatch):
    monkeypatch.setattr(burp_web_validation, "BurpMcpProvider", _ProviderStub)

    report = run_burp_web_lifecycle_validation(
        target_url="https://example.com/api/resource?id=1",
        scope_allowed_domains=("example.com",),
        scope_denied_domains=(),
    )

    payload = report.to_dict()
    assert payload["phase_status"]["phase_1"] == "PASSED"
    assert payload["mutations_tested"] > 0
    assert "baseline_request" in payload
    assert isinstance(payload["anomalies_detected"], list)
    assert payload["session_valid"] is True
    assert "retest_summary" in payload
