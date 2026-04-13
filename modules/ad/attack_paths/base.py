"""ReconForge AD Attack Path Base — shared interface for path builders.

Author: Andrews Ferreira
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AttackChain:
    """A single attack chain with steps and metadata."""
    name: str
    description: str
    steps: List[str]
    risk: str = "medium"  # critical, high, medium, low
    prerequisites: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
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
    chains: List[AttackChain] = field(default_factory=list)
    suggestions: List[NextStepSuggestion] = field(default_factory=list)


class AttackPathBuilderBase(ABC):
    """Abstract base for all attack path builders."""

    BUILDER_NAME: str = "base"

    @abstractmethod
    def build(
        self,
        analysis_data: Dict[str, Any],
        target: str = "",
        domain: str = "",
        **kwargs,
    ) -> AttackPathResult:
        """Build attack paths from analyzer output."""
        ...
