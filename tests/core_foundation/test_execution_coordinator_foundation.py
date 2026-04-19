from datetime import datetime, timedelta, timezone

from core.adapters.base_adapter import ProviderAdapter
from core.adapters.contracts import AdapterActionRequest, AdapterActionResult
from core.orchestrator.execution_coordinator import (
    ExecutionCoordinator,
    default_passthrough_normalizer,
    in_memory_evidence_writer,
)
from core.orchestrator.module_router import ModuleRouter
from core.policy.scope_policy import ScopePolicy, ScopeValidator
from core.schemas.contracts import ExecutionRequest, Target


class DummyAdapter(ProviderAdapter):
    adapter_id = "dummy"

    def execute(self, request: AdapterActionRequest) -> AdapterActionResult:
        return AdapterActionResult(provider="dummy", status="success", raw={"service": "http", "port": 80})


def test_execution_coordinator_blocks_out_of_scope_request():
    router = ModuleRouter()
    router.register("dummy", DummyAdapter())
    evidence_store: list[dict] = []
    coordinator = ExecutionCoordinator(
        router=router,
        scope_validator=ScopeValidator(),
        normalizer=default_passthrough_normalizer,
        evidence_writer=in_memory_evidence_writer(evidence_store),
    )

    request = ExecutionRequest(
        run_id="r1",
        initiated_by="tester",
        target=Target(value="evil.com", kind="domain"),
        provider="dummy",
        action="discover",
        action_class="discovery",
    )
    policy = ScopePolicy(
        scope_id="s1",
        approval_id="APP-1",
        valid_until=datetime.now(timezone.utc) + timedelta(hours=1),
        allowed_domains=("example.com",),
    )

    result = coordinator.execute(request, policy)

    assert result.status == "blocked"
    assert evidence_store[-1]["status"] == "blocked"


def test_execution_coordinator_executes_in_scope_request_and_normalizes():
    router = ModuleRouter()
    router.register("dummy", DummyAdapter())
    evidence_store: list[dict] = []
    coordinator = ExecutionCoordinator(
        router=router,
        scope_validator=ScopeValidator(),
        normalizer=default_passthrough_normalizer,
        evidence_writer=in_memory_evidence_writer(evidence_store),
    )

    request = ExecutionRequest(
        run_id="r2",
        initiated_by="tester",
        target=Target(value="api.example.com", kind="domain"),
        provider="dummy",
        action="discover",
        action_class="discovery",
    )
    policy = ScopePolicy(
        scope_id="s2",
        approval_id="APP-1",
        valid_until=datetime.now(timezone.utc) + timedelta(hours=1),
        allowed_domains=("example.com",),
    )

    result = coordinator.execute(request, policy)

    assert result.status == "success"
    assert result.normalized
    assert evidence_store[-1]["status"] == "success"
