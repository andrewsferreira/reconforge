import sys
import types
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

from core.adapters.burp.exceptions import BurpOutOfScopeError
from core.adapters.burp.models import NormalizedBurpHttpRecord

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NORMALIZER_PATH = PROJECT_ROOT / "reconforge" / "normalizers" / "http.py"
COLLECTOR_PATH = PROJECT_ROOT / "reconforge" / "collectors" / "http_collector.py"

if "reconforge" not in sys.modules:
    pkg = types.ModuleType("reconforge")
    pkg.__path__ = [str(PROJECT_ROOT / "reconforge")]
    sys.modules["reconforge"] = pkg
if "reconforge.normalizers" not in sys.modules:
    pkg = types.ModuleType("reconforge.normalizers")
    pkg.__path__ = [str(PROJECT_ROOT / "reconforge" / "normalizers")]
    sys.modules["reconforge.normalizers"] = pkg

normalizer_spec = spec_from_file_location("reconforge.normalizers.http", NORMALIZER_PATH)
assert normalizer_spec and normalizer_spec.loader
normalizer_module = module_from_spec(normalizer_spec)
sys.modules["reconforge.normalizers.http"] = normalizer_module
normalizer_spec.loader.exec_module(normalizer_module)

collector_spec = spec_from_file_location("reconforge.collectors.http_collector", COLLECTOR_PATH)
assert collector_spec and collector_spec.loader
collector_module = module_from_spec(collector_spec)
sys.modules["reconforge.collectors.http_collector"] = collector_module
collector_spec.loader.exec_module(collector_module)

HttpCollector = collector_module.HttpCollector


class _ProviderStub:
    def __init__(self):
        self._history = []
        self._request = []
        self.block_request = False

    def send_http1_request(self, arguments):
        if self.block_request:
            raise BurpOutOfScopeError("blocked")
        return list(self._request)

    def send_http2_request(self, arguments):
        return self.send_http1_request(arguments)

    def get_proxy_http_history(self, arguments):
        return list(self._history)

    def get_proxy_http_history_regex(self, arguments):
        return [r for r in self._history if arguments.get("regex") == ".*" or "admin" in r.url]


def test_empty_history_response():
    provider = _ProviderStub()
    collector = HttpCollector(provider)

    observations = collector.collect_proxy_history()

    assert observations == []
    summary = collector.summarize(observations)
    assert summary["total_observations"] == 0


def test_multiple_history_entries_normalized():
    provider = _ProviderStub()
    provider._history = [
        NormalizedBurpHttpRecord(url="https://a.example.com/", host="a.example.com", method="GET", status_code=200),
        NormalizedBurpHttpRecord(url="https://b.example.com/admin", host="b.example.com", method="POST", status_code=403),
    ]
    collector = HttpCollector(provider)

    observations = collector.collect_proxy_history()

    assert len(observations) == 2
    assert observations[0].host == "a.example.com"
    assert observations[1].response_status == 403


def test_request_collection_success():
    provider = _ProviderStub()
    provider._request = [
        NormalizedBurpHttpRecord(url="https://example.com/submit", host="example.com", method="POST", status_code=201)
    ]
    collector = HttpCollector(provider)

    observation = collector.collect_request("https://example.com/submit")

    assert observation.host == "example.com"
    assert observation.response_status == 201
    assert observation.source_tool == "send_http1_request"


def test_blocked_request_due_to_scope_bubbles_up():
    provider = _ProviderStub()
    provider.block_request = True
    collector = HttpCollector(provider)

    with pytest.raises(BurpOutOfScopeError):
        collector.collect_request("https://blocked.example.com")
