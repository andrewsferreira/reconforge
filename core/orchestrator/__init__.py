"""Foundational orchestration package."""

from core.orchestrator.execution_coordinator import (
    ExecutionCoordinator,
    default_passthrough_normalizer,
    in_memory_evidence_writer,
)
from core.orchestrator.module_router import ModuleRouter
from core.orchestrator.workflow_engine import WorkflowPlan, WorkflowStep

__all__ = [
    "ExecutionCoordinator",
    "ModuleRouter",
    "WorkflowPlan",
    "WorkflowStep",
    "default_passthrough_normalizer",
    "in_memory_evidence_writer",
]
