"""Foundational execution coordinator for Model 1 orchestration.

The coordinator enforces deterministic ordering:
scope validation -> adapter execution -> normalization envelope.
"""

from __future__ import annotations

import time
from dataclasses import asdict
from typing import Callable, List

from core.adapters.contracts import AdapterActionRequest
from core.orchestrator.module_router import ModuleRouter
from core.policy.scope_policy import ScopeDecision, ScopePolicy, ScopeValidator
from core.schemas.contracts import (
    EvidenceItem,
    ExecutionRequest,
    ExecutionResult,
    NormalizedObservation,
)

Normalizer = Callable[[dict, ExecutionRequest], List[NormalizedObservation]]
EvidenceWriter = Callable[[EvidenceItem], str]


class ExecutionCoordinator:
    """Coordinate execution while preserving policy and evidence guarantees."""

    def __init__(
        self,
        *,
        router: ModuleRouter,
        scope_validator: ScopeValidator,
        normalizer: Normalizer,
        evidence_writer: EvidenceWriter,
    ):
        self.router = router
        self.scope_validator = scope_validator
        self.normalizer = normalizer
        self.evidence_writer = evidence_writer

    def execute(self, request: ExecutionRequest, scope_policy: ScopePolicy) -> ExecutionResult:
        started = time.time()
        started_iso = ExecutionResult.now_iso()

        decision = self.scope_validator.validate(request, scope_policy)
        if not decision.allowed:
            return self._blocked_result(request, started, started_iso, decision)

        adapter = self.router.get(request.provider)
        adapter_request = AdapterActionRequest(
            run_id=request.run_id,
            target=request.target.value,
            action=request.action,
            timeout_seconds=request.timeout_seconds,
            parameters=dict(request.parameters),
        )

        adapter_result = adapter.execute_safe(adapter_request)
        normalized = self.normalizer(adapter_result.raw, request)

        evidence = EvidenceItem(
            evidence_id=f"ev_{request.run_id}_{request.provider}_{request.action}",
            run_id=request.run_id,
            timestamp=ExecutionResult.now_iso(),
            provider=request.provider,
            target=request.target.value,
            action=request.action,
            raw_ref="inline:raw",
            normalized_ref="inline:normalized",
            status="success" if adapter_result.status == "success" else "failed",
            error=adapter_result.error,
        )
        self.evidence_writer(evidence)

        return ExecutionResult(
            run_id=request.run_id,
            provider=request.provider,
            target=request.target.value,
            action=request.action,
            status="success" if adapter_result.status == "success" else "failed",
            started_at=started_iso,
            finished_at=ExecutionResult.now_iso(),
            duration_seconds=round(time.time() - started, 4),
            raw_result=adapter_result.raw,
            normalized=normalized,
            error=adapter_result.error,
        )

    def _blocked_result(
        self,
        request: ExecutionRequest,
        started: float,
        started_iso: str,
        decision: ScopeDecision,
    ) -> ExecutionResult:
        evidence = EvidenceItem(
            evidence_id=f"ev_{request.run_id}_{request.provider}_{request.action}_blocked",
            run_id=request.run_id,
            timestamp=ExecutionResult.now_iso(),
            provider=request.provider,
            target=request.target.value,
            action=request.action,
            raw_ref="",
            normalized_ref="",
            status="blocked",
            error=decision.reason,
        )
        self.evidence_writer(evidence)

        return ExecutionResult(
            run_id=request.run_id,
            provider=request.provider,
            target=request.target.value,
            action=request.action,
            status="blocked",
            started_at=started_iso,
            finished_at=ExecutionResult.now_iso(),
            duration_seconds=round(time.time() - started, 4),
            raw_result={"blocked_reason": decision.reason},
            normalized=[],
            error=decision.reason,
        )


def default_passthrough_normalizer(raw: dict, request: ExecutionRequest) -> List[NormalizedObservation]:
    """Safe default normalizer for incremental adoption."""
    return [
        NormalizedObservation(
            observation_type="generic",
            target=request.target.value,
            attributes=dict(raw),
            evidence_id=f"ev_{request.run_id}_{request.provider}_{request.action}",
        )
    ]


def in_memory_evidence_writer(store: list[dict]) -> EvidenceWriter:
    """Simple test/dev evidence writer for deterministic unit tests."""

    def _write(item: EvidenceItem) -> str:
        store.append(asdict(item))
        return item.evidence_id

    return _write
