"""Validation-facing models that extend core Burp integration models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from core.adapters.burp.config import BurpMcpConfig as ValidationConfig
from core.adapters.burp.models import BurpCapability as ToolCapability
from core.adapters.burp.models import BurpSessionState as ConnectionStatus


@dataclass
class ValidationError:
    stage: str
    error_type: str
    message: str
    recoverable: bool = False


@dataclass
class SafeExecutionResult:
    tool_name: str = ""
    attempted: bool = False
    success: bool = False
    latency_ms: float = 0.0
    response_shape_valid: bool = False
    error: str = ""


@dataclass
class ValidationReport:
    generated_at: str
    target_url: str
    success: bool
    recommendation: str
    connection: ConnectionStatus
    tool_count: int = 0
    tools: List[ToolCapability] = field(default_factory=list)
    missing_features: List[str] = field(default_factory=list)
    restricted_features: List[str] = field(default_factory=list)
    safe_execution: SafeExecutionResult = field(default_factory=SafeExecutionResult)
    errors: List[ValidationError] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self):
        from dataclasses import asdict

        return asdict(self)
