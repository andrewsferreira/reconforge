"""ReconForge AD Attack Path Base — shared interface for path builders.

Author: Andrews Ferreira
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackChain:
    """A single attack chain with steps and metadata."""
    name: str
    description: str
    steps: list[str]
    risk: str = "medium"  # critical, high, medium, low
    prerequisites: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    source: str = ""  # Starting point
    target: str = ""  # End goal
    chain_type: str = ""  # e.g. kerberoast, delegation, acl


@dataclass
class NextStepSuggestion:
    """A suggested next command for the operator."""
    command: str
    justification: str
    priority: str = "medium"  # critical, high, medium, low


@dataclass
class AttackPathResult:
    """Output from an attack path builder."""
    builder: str = ""
    chains: list[AttackChain] = field(default_factory=list)
    suggestions: list[NextStepSuggestion] = field(default_factory=list)


class AttackPathBuilderBase(ABC):
    """Abstract base for all attack path builders."""

    BUILDER_NAME: str = "base"

    @abstractmethod
    def build(
        self,
        analysis_data: dict[str, Any],
        target: str = "",
        domain: str = "",
        **kwargs,
    ) -> AttackPathResult:
        """Build attack paths from analyzer output."""
        ...
