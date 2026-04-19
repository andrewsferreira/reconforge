"""Base provider adapter with deterministic safety wrappers."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Callable, Optional

from core.adapters.contracts import AdapterActionRequest, AdapterActionResult


AuditHook = Callable[[str, dict], None]


class ProviderAdapter(ABC):
    """Abstract provider adapter.

    Adapters are translation boundaries only; they must not decide workflow
    sequencing or scope policy.
    """

    adapter_id: str = "base"
    max_retries: int = 1

    def __init__(self, *, audit_hook: Optional[AuditHook] = None):
        self.audit_hook = audit_hook

    @abstractmethod
    def execute(self, request: AdapterActionRequest) -> AdapterActionResult:
        """Execute one provider action."""

    def validate_request(self, request: AdapterActionRequest) -> None:
        if not request.run_id:
            raise ValueError("adapter request missing run_id")
        if not request.target:
            raise ValueError("adapter request missing target")
        if not request.action:
            raise ValueError("adapter request missing action")
        if request.timeout_seconds <= 0:
            raise ValueError("adapter request timeout must be positive")

    def validate_response(self, result: AdapterActionResult) -> None:
        if result.status not in {"success", "failed"}:
            raise ValueError("adapter result status must be success|failed")
        if not result.provider:
            raise ValueError("adapter result missing provider")

    def execute_safe(self, request: AdapterActionRequest) -> AdapterActionResult:
        """Execute with validation, retry bounds, and audit hooks."""
        self.validate_request(request)

        last_error = ""
        for attempt in range(1, self.max_retries + 1):
            started = time.time()
            self._emit("adapter_attempt_start", {
                "adapter_id": self.adapter_id,
                "attempt": attempt,
                "run_id": request.run_id,
                "target": request.target,
                "action": request.action,
            })
            try:
                result = self.execute(request)
                self.validate_response(result)
                self._emit("adapter_attempt_success", {
                    "adapter_id": self.adapter_id,
                    "attempt": attempt,
                    "duration_seconds": round(time.time() - started, 4),
                    "run_id": request.run_id,
                    "status": result.status,
                })
                return result
            except Exception as exc:
                last_error = str(exc)
                self._emit("adapter_attempt_failure", {
                    "adapter_id": self.adapter_id,
                    "attempt": attempt,
                    "duration_seconds": round(time.time() - started, 4),
                    "run_id": request.run_id,
                    "error": last_error,
                })

        return AdapterActionResult(
            provider=self.adapter_id,
            status="failed",
            raw={},
            error=last_error or "adapter execution failed",
        )

    def _emit(self, event: str, payload: dict) -> None:
        if self.audit_hook:
            self.audit_hook(event, payload)
