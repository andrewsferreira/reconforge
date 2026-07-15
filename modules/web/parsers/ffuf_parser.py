"""ReconForge ffuf Parser - Parse ffuf JSON output.

Author: Andrews Ferreira

Extracts:
- Discovered paths with status codes, sizes, and word counts
- Virtual hosts
- Categorises findings by HTTP status code
"""

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FfufEntry:
    """A single ffuf result entry."""
    url: str = ""
    status: int = 0
    length: int = 0
    words: int = 0
    lines: int = 0
    input_word: str = ""


@dataclass
class FfufResult:
    """Complete ffuf scan result."""
    entries: list[FfufEntry] = field(default_factory=list)
    command_line: str = ""
    raw_output: str = ""

    @property
    def by_status(self) -> dict[int, list[FfufEntry]]:
        groups: dict[int, list[FfufEntry]] = {}
        for e in self.entries:
            groups.setdefault(e.status, []).append(e)
        return groups


class FfufParser:
    """Parse ffuf JSON output into structured data."""

    def parse_json(self, json_path: Path) -> FfufResult:
        """Parse ffuf JSON output file.

        Args:
            json_path: Path to ffuf JSON output.

        Returns:
            FfufResult with parsed entries.
        """
        result = FfufResult()

        if not json_path.is_file():
            return result

        try:
            raw = json_path.read_text(encoding="utf-8")
            result.raw_output = raw
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            return result

        result.command_line = data.get("commandline", "")
        if not result.command_line:
            result.command_line = data.get("commandLine", "")

        for r in data.get("results", []):
            input_data = r.get("input", {})
            if isinstance(input_data, dict):
                input_word = input_data.get("FUZZ", "")
            else:
                input_word = str(input_data)

            entry = FfufEntry(
                url=r.get("url", ""),
                status=self._to_int(r.get("status", 0)),
                length=self._to_int(r.get("length", 0)),
                words=self._to_int(r.get("words", 0)),
                lines=self._to_int(r.get("lines", 0)),
                input_word=input_word,
            )
            result.entries.append(entry)

        return result

    @staticmethod
    def status_to_severity(status: int) -> str:
        if 500 <= status <= 599:
            return "medium"
        if status in (401, 403):
            return "low"
        return "info"

    @staticmethod
    def status_recommendation(status: int) -> str:
        recs = {
            200: "Review content for sensitive information.",
            301: "Follow redirect and examine destination.",
            302: "Follow redirect and examine destination.",
            401: "Requires authentication – attempt credential attacks if in scope.",
            403: "Access forbidden – may indicate hidden content. Try bypass techniques.",
            405: "Method not allowed – test alternative HTTP methods.",
            500: "Internal server error – potential for exploitation.",
        }
        return recs.get(status, "Review endpoint manually.")

    @staticmethod
    def _to_int(value, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
