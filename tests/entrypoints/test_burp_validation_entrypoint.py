import json
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.adapters.burp.models import (
    BurpCapability,
    BurpProviderState,
    BurpSessionState,
    NormalizedBurpHttpRecord,
)

ENTRYPOINT_PATH = Path(__file__).resolve().parents[2] / "reconforge" / "entrypoints" / "burp_validation.py"
SPEC = spec_from_file_location("_burp_validation_entrypoint", ENTRYPOINT_PATH)
assert SPEC and SPEC.loader
burp_validation = module_from_spec(SPEC)
sys.modules["_burp_validation_entrypoint"] = burp_validation
SPEC.loader.exec_module(burp_validation)

FAILED = burp_validation.FAILED
PARTIAL = burp_validation.PARTIAL
READY = burp_validation.READY
render_validation_console_summary = burp_validation.render_validation_console_summary
validate_burp_provider = burp_validation.validate_burp_provider


class _ProviderSuccess:
    def __init__(self, config):
        self._state = BurpProviderState(
            session=BurpSessionState(
                base_url=config.base_url,
                sse_connected=True,
                session_id="sess-123",
                message_endpoint="/rpc?sessionId=sess-123",
            ),
            discovered_tools=[BurpCapability(name="get_proxy_http_history", enabled=True)],
            enabled_tools=["get_proxy_http_history"],
            disabled_tools=["burp.scanner.start"],
        )

    def start(self):
        return self._state

    def stop(self):
        return None

    def get_proxy_http_history(self, arguments):
        assert arguments == {}
        return [
            NormalizedBurpHttpRecord(tool_name="get_proxy_http_history", provider="burp_mcp")
        ]

    def get_proxy_http_history_regex(self, arguments):
        raise AssertionError("should not call regex tool when history tool exists")


class _ProviderEmptyButValid:
    def __init__(self, config):
        self._state = BurpProviderState(
            session=BurpSessionState(base_url=config.base_url, sse_connected=True, session_id="sess-999"),
            discovered_tools=[BurpCapability(name="get_proxy_http_history", enabled=True)],
            enabled_tools=["get_proxy_http_history"],
            disabled_tools=[],
        )

    def start(self):
        return self._state

    def stop(self):
        return None

    def get_proxy_http_history(self, arguments):
        assert arguments == {}
        return []


class _ProviderNoSafeTool:
    def __init__(self, config):
        self._state = BurpProviderState(
            session=BurpSessionState(base_url=config.base_url, sse_connected=True, session_id="sess-456"),
            discovered_tools=[BurpCapability(name="burp.project.save", enabled=False, reason="blocked_by_policy")],
            enabled_tools=[],
            disabled_tools=["burp.project.save"],
        )

    def start(self):
        return self._state

    def stop(self):
        return None


class _ProviderFailure:
    def __init__(self, config):
        self._state = BurpProviderState(session=BurpSessionState(base_url=config.base_url))

    def start(self):
        from core.adapters.burp.exceptions import BurpNotReachableError

        raise BurpNotReachableError("connection refused")

    def stop(self):
        return None


def test_validate_burp_provider_ready(monkeypatch):
    monkeypatch.setattr(burp_validation, "BurpMcpProvider", _ProviderSuccess)

    result = validate_burp_provider("http://127.0.0.1:9876")

    assert result.provider_name == "burp_mcp"
    assert result.provider_type == "mcp_adapter"
    assert result.connection_status == "CONNECTED"
    assert result.session_status == "ESTABLISHED"
    assert result.capability_discovery_status == "SUCCESS"
    assert result.safe_test_name == "get_proxy_http_history"
    assert result.safe_test_status == "SUCCESS"
    assert result.session_id == "sess-123"
    assert result.total_tools == 1
    assert result.allowed_tools == ["get_proxy_http_history"]
    assert result.blocked_tools == ["burp.scanner.start"]
    assert result.readiness_status == READY

    summary = render_validation_console_summary(result)
    assert "Readiness status: READY" in summary


def test_validate_burp_provider_empty_but_valid_result(monkeypatch):
    monkeypatch.setattr(burp_validation, "BurpMcpProvider", _ProviderEmptyButValid)

    result = validate_burp_provider("http://127.0.0.1:9876")

    assert result.safe_test_status == "SUCCESS"
    assert result.normalized_record_count == 0
    assert "empty" in result.safe_test_summary.lower()
    assert result.readiness_status == READY


def test_validate_burp_provider_partial_without_safe_tool(monkeypatch):
    monkeypatch.setattr(burp_validation, "BurpMcpProvider", _ProviderNoSafeTool)

    result = validate_burp_provider("http://127.0.0.1:9876")

    assert result.connection_status == "CONNECTED"
    assert result.safe_test_status == "DENIED_BY_POLICY"
    assert result.readiness_status == PARTIAL
    assert result.warnings


def test_validate_burp_provider_failed_when_unreachable(monkeypatch):
    monkeypatch.setattr(burp_validation, "BurpMcpProvider", _ProviderFailure)

    result = validate_burp_provider("http://127.0.0.1:1")

    assert result.connection_status == "UNREACHABLE"
    assert result.session_status == "FAILED"
    assert result.readiness_status == FAILED
    assert result.errors

    payload = json.dumps(result.to_dict())
    assert "connection refused" in payload
