from core.adapters.base_adapter import ProviderAdapter
from core.adapters.contracts import AdapterActionRequest, AdapterActionResult


class FlakyAdapter(ProviderAdapter):
    adapter_id = "flaky"
    max_retries = 2

    def __init__(self):
        self.calls = 0
        super().__init__()

    def execute(self, request: AdapterActionRequest) -> AdapterActionResult:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("transient")
        return AdapterActionResult(provider=self.adapter_id, status="success", raw={"ok": True})


class InvalidResponseAdapter(ProviderAdapter):
    adapter_id = "invalid"

    def execute(self, request: AdapterActionRequest) -> AdapterActionResult:
        return AdapterActionResult(provider="", status="success", raw={})


def test_provider_adapter_retries_and_succeeds():
    adapter = FlakyAdapter()
    request = AdapterActionRequest(
        run_id="run-1",
        target="example.com",
        action="discovery",
        timeout_seconds=10,
    )

    result = adapter.execute_safe(request)

    assert result.status == "success"
    assert adapter.calls == 2


def test_provider_adapter_returns_failed_on_validation_error():
    adapter = InvalidResponseAdapter()
    request = AdapterActionRequest(
        run_id="run-1",
        target="example.com",
        action="discovery",
        timeout_seconds=10,
    )

    result = adapter.execute_safe(request)

    assert result.status == "failed"
    assert "missing provider" in result.error
