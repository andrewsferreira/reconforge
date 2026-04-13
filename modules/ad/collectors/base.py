"""ReconForge AD Collector Base — shared interface for all collectors.

Author: Andrews Ferreira
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logger import ReconLogger
from core.runner import Runner
from core.opsec_checks import OpsecChecker


@dataclass
class CollectorResult:
    """Standardised output from any collector.

    Attributes:
        source: Collector name / tool that produced the data.
        success: Whether collection succeeded.
        data: Arbitrary structured data (specific to each collector).
        raw_output: Optional raw text output for debugging.
        errors: List of non-fatal error messages.
    """
    source: str = ""
    success: bool = False
    data: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    errors: List[str] = field(default_factory=list)


class CollectorBase(ABC):
    """Abstract base for all AD data collectors."""

    COLLECTOR_NAME: str = "base"

    def __init__(
        self,
        logger: ReconLogger,
        runner: Runner,
        opsec: OpsecChecker,
        output_dir: Path,
        opsec_mode: str = "normal",
    ) -> None:
        self.logger = logger
        self.runner = runner
        self.opsec = opsec
        self.output_dir = Path(output_dir)
        self.opsec_mode = opsec_mode

    @abstractmethod
    def collect(
        self,
        target: str,
        domain: str = "",
        base_dn: str = "",
        username: str = "",
        password: str = "",
        **kwargs,
    ) -> CollectorResult:
        """Gather data and return a CollectorResult."""
        ...
