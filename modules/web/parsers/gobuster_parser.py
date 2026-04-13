"""ReconForge Gobuster Parser - Parse gobuster text output.

Author: Andrews Ferreira

Extracts:
- Discovered paths with HTTP status codes and response sizes
- DNS subdomain results
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class GobusterEntry:
    """A single gobuster result entry."""
    path: str = ""
    full_url: str = ""
    status: int = 0
    size: int = 0


@dataclass
class GobusterResult:
    """Complete gobuster scan result."""
    entries: List[GobusterEntry] = field(default_factory=list)
    raw_output: str = ""


class GobusterParser:
    """Parse gobuster text output into structured data."""

    PATH_RE = re.compile(r"^(/\S+)")
    STATUS_RE = re.compile(r"(?:\(\s*Status:\s*(\d+)\s*\)|\[\s*Status:\s*(\d+)\s*\])")
    SIZE_RE = re.compile(r"\[\s*(?:Size|Length):\s*(\d+)\s*\]")

    def parse_dir(self, output_path: Path, base_url: str = "") -> GobusterResult:
        """Parse gobuster dir mode output.

        Args:
            output_path: Path to gobuster output file.
            base_url: Base URL to prepend to paths.

        Returns:
            GobusterResult with parsed entries.
        """
        result = GobusterResult()

        if not output_path.is_file():
            return result

        raw = output_path.read_text(encoding="utf-8", errors="replace")
        result.raw_output = raw

        result.entries = self._parse_entries(raw, base_url)

        return result

    def parse_text(self, text: str, base_url: str = "") -> GobusterResult:
        """Parse gobuster text from stdout (fallback).

        Args:
            text: Gobuster stdout text.
            base_url: Base URL to prepend.

        Returns:
            GobusterResult with parsed entries.
        """
        result = GobusterResult(raw_output=text)

        result.entries = self._parse_entries(text, base_url)

        return result

    def _parse_entries(self, text: str, base_url: str = "") -> List[GobusterEntry]:
        entries: List[GobusterEntry] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            path_match = self.PATH_RE.search(line)
            status_match = self.STATUS_RE.search(line)
            if not path_match or not status_match:
                continue

            size_match = self.SIZE_RE.search(line)
            status = status_match.group(1) or status_match.group(2) or "0"
            size = int(size_match.group(1)) if size_match else 0
            path = path_match.group(1)

            entries.append(GobusterEntry(
                path=path,
                full_url=f"{base_url.rstrip('/')}{path}" if base_url else path,
                status=int(status),
                size=size,
            ))

        return entries
