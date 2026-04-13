"""ReconForge Arjun Parser - Parse Arjun JSON output.

Author: Andrews Ferreira

Extracts:
- Discovered HTTP parameters per URL
- Parameter methods (GET, POST, JSON)
- Parameter types and locations
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


@dataclass
class ArjunParam:
    """A single discovered parameter."""
    name: str = ""
    method: str = "GET"
    url: str = ""
    reason: str = ""


@dataclass
class ArjunResult:
    """Complete Arjun scan result."""
    params: List[ArjunParam] = field(default_factory=list)
    raw_output: str = ""
    urls_scanned: List[str] = field(default_factory=list)

    @property
    def by_url(self) -> Dict[str, List[ArjunParam]]:
        groups: Dict[str, List[ArjunParam]] = {}
        for p in self.params:
            groups.setdefault(p.url, []).append(p)
        return groups

    @property
    def param_names(self) -> List[str]:
        """Return unique parameter names."""
        return list(set(p.name for p in self.params))

    @property
    def sensitive_params(self) -> List[ArjunParam]:
        """Return parameters that look security-sensitive."""
        sensitive_keywords = (
            "token", "key", "secret", "password", "passwd", "auth",
            "api_key", "apikey", "access", "session", "admin",
            "debug", "test", "internal", "id", "user_id", "role",
        )
        return [
            p for p in self.params
            if any(kw in p.name.lower() for kw in sensitive_keywords)
        ]


class ArjunParser:
    """Parse Arjun JSON output into structured data."""

    def parse_json(self, json_path: Path) -> ArjunResult:
        """Parse Arjun JSON output file.

        Arjun outputs JSON in the format::

            {
                "http://target.com/api/endpoint": [
                    "param1", "param2", ...
                ]
            }

        Args:
            json_path: Path to Arjun JSON output.

        Returns:
            ArjunResult with parsed parameters.
        """
        result = ArjunResult()

        if not json_path.is_file():
            return result

        try:
            raw = json_path.read_text(encoding="utf-8")
            result.raw_output = raw
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            return result

        if isinstance(data, dict):
            for url, params in data.items():
                result.urls_scanned.append(url)
                if isinstance(params, list):
                    for param_name in params:
                        result.params.append(ArjunParam(
                            name=str(param_name),
                            url=url,
                        ))
                elif isinstance(params, dict):
                    # Alternative format: {url: {"GET": [params], "POST": [params]}}
                    for method, param_list in params.items():
                        if isinstance(param_list, list):
                            for param_name in param_list:
                                result.params.append(ArjunParam(
                                    name=str(param_name),
                                    method=method,
                                    url=url,
                                ))

        return result

    @staticmethod
    def param_to_severity(param_name: str) -> str:
        """Map parameter name to finding severity."""
        high_risk = ("token", "key", "secret", "password", "admin", "role",
                     "debug", "internal", "auth")
        medium_risk = ("id", "user", "account", "session", "api_key")

        name_lower = param_name.lower()
        if any(kw in name_lower for kw in high_risk):
            return "high"
        if any(kw in name_lower for kw in medium_risk):
            return "medium"
        return "low"
