"""ReconForge AD Reporter Base — shared interface for reporters.

Author: Andrews Ferreira
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List


class ReporterBase(ABC):
    """Abstract base for all AD reporters."""

    REPORTER_NAME: str = "base"

    @abstractmethod
    def generate(self, data: Dict[str, Any], **kwargs) -> str:
        """Generate a markdown report from analysis data.

        Returns:
            Markdown-formatted report string.
        """
        ...

    def save(self, content: str, path: Path) -> None:
        """Save report to file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
