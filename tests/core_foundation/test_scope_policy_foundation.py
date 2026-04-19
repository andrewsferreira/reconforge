from datetime import datetime, timedelta, timezone

from core.policy.scope_policy import ScopePolicy, ScopeValidator
from core.schemas.contracts import ExecutionRequest, Target


def _base_request(target: str, *, mode: str = "safe", dry_run: bool = False) -> ExecutionRequest:
    return ExecutionRequest(
        run_id="run-1",
        initiated_by="tester",
        target=Target(value=target, kind="unknown"),
        provider="dummy",
        action="discover",
        action_class="discovery",
        mode=mode,  # type: ignore[arg-type]
        dry_run=dry_run,
        timeout_seconds=30,
    )


def test_scope_validator_allows_domain_and_subdomain():
    policy = ScopePolicy(
        scope_id="scope-1",
        approval_id="APP-1",
        valid_until=datetime.now(timezone.utc) + timedelta(hours=1),
        allowed_domains=("example.com",),
    )
    validator = ScopeValidator()

    decision = validator.validate(_base_request("api.example.com"), policy)

    assert decision.allowed is True


def test_scope_validator_blocks_denylist_even_when_domain_matches():
    policy = ScopePolicy(
        scope_id="scope-1",
        approval_id="APP-1",
        valid_until=datetime.now(timezone.utc) + timedelta(hours=1),
        allowed_domains=("example.com",),
        explicit_denylist=("admin.example.com",),
    )
    validator = ScopeValidator()

    decision = validator.validate(_base_request("admin.example.com"), policy)

    assert decision.allowed is False
    assert "denylist" in decision.reason


def test_scope_validator_blocks_when_dry_run_only_policy_violated():
    policy = ScopePolicy(
        scope_id="scope-1",
        approval_id="APP-1",
        valid_until=datetime.now(timezone.utc) + timedelta(hours=1),
        explicit_allow_targets=("10.10.10.10",),
        dry_run_only=True,
    )
    validator = ScopeValidator()

    decision = validator.validate(_base_request("10.10.10.10", dry_run=False), policy)

    assert decision.allowed is False
    assert "dry-run" in decision.reason
