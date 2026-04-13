"""ReconForge API ffuf Parser - Parse ffuf JSON output for API endpoints.

Author: Andrews Ferreira

Extracts:
- Discovered API endpoints with status codes, sizes, and word counts
- Categorises findings by HTTP status code
- API-specific severity mapping
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


@dataclass
class FfufApiEntry:
    """A single ffuf result entry for API scanning."""
    url: str = ""
    status: int = 0
    length: int = 0
    words: int = 0
    lines: int = 0
    input_word: str = ""
    content_type: str = ""


@dataclass
class FfufApiResult:
    """Complete ffuf API scan result."""
    entries: List[FfufApiEntry] = field(default_factory=list)
    command_line: str = ""
    raw_output: str = ""

    @property
    def by_status(self) -> Dict[int, List[FfufApiEntry]]:
        groups: Dict[int, List[FfufApiEntry]] = {}
        for e in self.entries:
            groups.setdefault(e.status, []).append(e)
        return groups

    @property
    def api_endpoints(self) -> List[FfufApiEntry]:
        """Return only entries that look like API endpoints."""
        api_indicators = ("/api/", "/v1/", "/v2/", "/v3/", "/graphql",
                          "/rest/", "/json", "/xml", "/swagger", "/openapi")
        return [
            e for e in self.entries
            if any(ind in e.url.lower() for ind in api_indicators)
            or e.status in (200, 201, 204)
        ]


class FfufApiParser:
    """Parse ffuf JSON output for API endpoint discovery."""

    def parse_json(self, json_path: Path) -> FfufApiResult:
        """Parse ffuf JSON output file.

        Args:
            json_path: Path to ffuf JSON output.

        Returns:
            FfufApiResult with parsed entries.
        """
        result = FfufApiResult()

        if not json_path.is_file():
            return result

        try:
            raw = json_path.read_text(encoding="utf-8")
            result.raw_output = raw
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            return result

        result.command_line = data.get("commandline", "")

        for r in data.get("results", []):
            entry = FfufApiEntry(
                url=r.get("url", ""),
                status=r.get("status", 0),
                length=r.get("length", 0),
                words=r.get("words", 0),
                lines=r.get("lines", 0),
                input_word=r.get("input", {}).get("FUZZ", ""),
                content_type=r.get("content-type", ""),
            )
            result.entries.append(entry)

        return result

    @staticmethod
    def status_to_severity(status: int) -> str:
        """Map HTTP status to finding severity for API context."""
        if status == 500:
            return "medium"
        if status in (401, 403):
            return "low"
        if status == 405:
            return "info"
        return "info"

    @staticmethod
    def classify_endpoint(url: str) -> str:
        """Classify an endpoint by sensitivity."""
        url_lower = url.lower()
        sensitive = ("admin", "auth", "login", "token", "secret", "key",
                     "password", "user", "account", "internal", "debug",
                     "graphql", "swagger", "openapi", "docs")
        for keyword in sensitive:
            if keyword in url_lower:
                return "sensitive"
        return "normal"
