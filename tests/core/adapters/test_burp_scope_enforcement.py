import pytest

from core.adapters.burp.config import BurpMcpConfig
from core.adapters.burp.exceptions import BurpMalformedTargetError, BurpOutOfScopeError
from core.adapters.burp.provider import BurpMcpProvider


class _StubClient:
    def __init__(self):
        self.called = False

    def has_capability(self, tool_name: str) -> bool:
        return tool_name in {"send_http1_request", "send_http2_request"}

    def call_tool(self, tool_name: str, arguments: dict):
        self.called = True
        return {
            "url": arguments.get("url", ""),
            "host": "example.com",
            "method": "GET",
            "statusCode": 200,
            "responseBodyLength": 1,
        }


def _provider_with_scope() -> BurpMcpProvider:
    provider = BurpMcpProvider(
        config=BurpMcpConfig(
            scope_allowed_domains=("example.com",),
            scope_denied_domains=("google.com",),
            scope_allow_subdomains=True,
        )
    )
    provider.client = _StubClient()  # type: ignore[assignment]
    return provider


def test_send_http1_request_blocks_when_target_out_of_scope():
    provider = _provider_with_scope()

    with pytest.raises(BurpOutOfScopeError):
        provider.send_http1_request({"url": "https://google.com/"})

    assert provider.last_scope_decision.reason == "explicitly_denied"
    assert provider.client.called is False  # type: ignore[attr-defined]


def test_send_http2_request_blocks_when_target_is_malformed():
    provider = _provider_with_scope()

    with pytest.raises(BurpMalformedTargetError):
        provider.send_http2_request({"url": "not-a-valid-url"})

    assert provider.last_scope_decision.reason == "malformed_target"
    assert provider.client.called is False  # type: ignore[attr-defined]


def test_send_http1_request_executes_when_target_allowed():
    provider = _provider_with_scope()

    normalized = provider.send_http1_request({"url": "https://api.example.com/path"})

    assert provider.last_scope_decision.in_scope is True
    assert provider.last_scope_decision.subdomain_match_used is True
    assert provider.client.called is True  # type: ignore[attr-defined]
    assert normalized
