"""ReconForge telemetry helpers for observability and audit."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Optional


@dataclass
class PhaseMetric:
    phase: str
    start_time: str
    end_time: str = ""
    duration_seconds: float = 0.0
    status: str = "pending"
    error: str = ""


class ModuleTelemetry:
    """Collect execution metadata and per-phase metrics for a module run."""

    def __init__(self, module_name: str, target: str, execution_id: Optional[str] = None):
        self.module_name = module_name
        self.target = target
        self.execution_id = execution_id or f"run_{uuid.uuid4().hex[:12]}"
        self.started_at = datetime.utcnow().isoformat()
        self.phase_metrics: Dict[str, PhaseMetric] = {}

    def run_phase(self, phase_name: str, fn: Callable[[], Any]) -> Any:
        start = datetime.utcnow()
        metric = PhaseMetric(phase=phase_name, start_time=start.isoformat(), status="running")
        self.phase_metrics[phase_name] = metric
        try:
            result = fn()
            metric.status = "success"
            return result
        except Exception as exc:
            metric.status = "failed"
            metric.error = str(exc)
            raise
        finally:
            end = datetime.utcnow()
            metric.end_time = end.isoformat()
            metric.duration_seconds = (end - start).total_seconds()

    def to_dict(self, runner_metrics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        runner_metrics = runner_metrics or {}
        total = runner_metrics.get("total_commands", 0)
        failed = runner_metrics.get("failed_commands", 0)
        error_rate = (failed / total) if total else 0.0

        return {
            "execution_id": self.execution_id,
            "module": self.module_name,
            "target": self.target,
            "started_at": self.started_at,
            "phases": {
                name: {
                    "start_time": m.start_time,
                    "end_time": m.end_time,
                    "duration_seconds": m.duration_seconds,
                    "status": m.status,
                    "error": m.error,
                }
                for name, m in self.phase_metrics.items()
            },
            "runner": {
                **runner_metrics,
                "error_rate": round(error_rate, 4),
            },
        }
