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

    # Gobuster dir output: /path (Status: 200) [Size: 1234]
    DIR_PATTERN = re.compile(
        r"(/\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]"
    )

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

        for match in self.DIR_PATTERN.finditer(raw):
            path = match.group(1)
            entry = GobusterEntry(
                path=path,
                full_url=f"{base_url.rstrip('/')}{path}" if base_url else path,
                status=int(match.group(2)),
                size=int(match.group(3)),
            )
            result.entries.append(entry)

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

        for match in self.DIR_PATTERN.finditer(text):
            path = match.group(1)
            result.entries.append(GobusterEntry(
                path=path,
                full_url=f"{base_url.rstrip('/')}{path}" if base_url else path,
                status=int(match.group(2)),
                size=int(match.group(3)),
            ))

        return result
