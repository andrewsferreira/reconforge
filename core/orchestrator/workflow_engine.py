"""Deterministic workflow primitives for foundational orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from core.schemas.contracts import ExecutionRequest


@dataclass(frozen=True)
class WorkflowStep:
    step_id: str
    request: ExecutionRequest


@dataclass
class WorkflowPlan:
    plan_id: str
    steps: List[WorkflowStep] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)

    def add_step(self, step: WorkflowStep) -> None:
        if any(s.step_id == step.step_id for s in self.steps):
            raise ValueError(f"duplicate step id: {step.step_id}")
        self.steps.append(step)
