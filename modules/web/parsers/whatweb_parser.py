"""ReconForge WhatWeb Parser - Parse WhatWeb JSON output.

Author: Andrews Ferreira

Extracts:
- Web technologies and frameworks
- Server software and versions
- CMS platforms
- Interesting HTTP headers
- Technology exposure findings
"""

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DetectedTechnology:
    """A detected web technology."""
    name: str
    version: str = ""
    category: str = "technology"  # technology, header, server, cms, framework
    confidence: str = "medium"
    raw_data: str = ""


@dataclass
class WhatwebResult:
    """Complete WhatWeb scan result."""
    target_url: str = ""
    technologies: list[DetectedTechnology] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    raw_output: str = ""

    @property
    def tech_names(self) -> list[str]:
        return [t.name for t in self.technologies]


class WhatwebParser:
    """Parse WhatWeb JSON output into structured data."""

    # Plugins that map to informational header findings
    HEADER_PLUGINS = {
        "Title", "UncommonHeaders", "X-Powered-By",
        "HTTPServer", "IP", "Country", "RedirectLocation",
    }
    def parse_json(self, json_path: Path) -> WhatwebResult:
        """Parse WhatWeb JSON log file.

        Args:
            json_path: Path to WhatWeb JSON output.

        Returns:
            WhatwebResult with structured data.
        """
        result = WhatwebResult()

        if not json_path.is_file():
            return result

        raw = json_path.read_text(encoding="utf-8", errors="replace")
        result.raw_output = raw

        if not raw.strip():
            return result

        entries = self._load_json_entries(raw)
        if not entries:
            return result

        for entry in entries:
            result.target_url = entry.get("target", result.target_url)
            plugins = entry.get("plugins", {})

            for plugin_name, plugin_data in plugins.items():
                version = self._extract_version(plugin_data)

                if plugin_name == "HTTPServer":
                    category = "server"
                elif plugin_name in self.HEADER_PLUGINS:
                    category = "header"
                elif plugin_name.lower() in ("wordpress", "joomla", "drupal",
                                              "magento", "shopify", "woocommerce"):
                    category = "cms"
                else:
                    category = "technology"

                tech = DetectedTechnology(
                    name=plugin_name,
                    version=version,
                    category=category,
                    confidence="high" if version else "medium",
                    raw_data=json.dumps(plugin_data, default=str)[:500],
                )
                result.technologies.append(tech)

                # Populate headers dict
                if category == "header" and version:
                    result.headers[plugin_name] = version

        return result

    def parse_text(self, text: str) -> WhatwebResult:
        """Parse WhatWeb text output (fallback).

        Args:
            text: WhatWeb stdout text.

        Returns:
            WhatwebResult with parsed data.
        """
        result = WhatwebResult(raw_output=text)
        # WhatWeb text: URL [status] Plugin[version], Plugin, ...
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("ERROR"):
                continue
            for part in line.split(","):
                part = part.strip()
                if "[" not in part or "]" not in part:
                    continue

                name, _, tail = part.partition("[")
                name = name.strip()
                value = tail.rsplit("]", 1)[0].strip()
                lower_name = name.lower()
                if not name or "://" in name or lower_name.startswith("http://") or lower_name.startswith("https://"):
                    continue
                if name.lower() in {"status", "redirected"}:
                    continue

                category = "technology"
                if name == "HTTPServer":
                    category = "server"
                elif name in self.HEADER_PLUGINS:
                    category = "header"
                elif name.lower() in ("wordpress", "joomla", "drupal",
                                       "magento", "shopify", "woocommerce"):
                    category = "cms"

                result.technologies.append(
                    DetectedTechnology(name=name, version=value, category=category)
                )
        return result

    @staticmethod
    def _load_json_entries(raw: str) -> list:
        """Load WhatWeb JSON which may be one-object-per-line or an array."""
        entries = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if line:
                try:
                    parsed = json.loads(line)
                    if isinstance(parsed, list):
                        entries.extend(parsed)
                    else:
                        entries.append(parsed)
                except json.JSONDecodeError:
                    continue

        if entries:
            return entries

        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return data
            return [data]
        except json.JSONDecodeError:
            return []

    @staticmethod
    def _extract_version(plugin_data) -> str:
        """Extract version string from WhatWeb plugin data."""
        if isinstance(plugin_data, dict):
            ver = plugin_data.get("version")
            if ver:
                return ver[0] if isinstance(ver, list) else str(ver)
            string = plugin_data.get("string")
            if string:
                return string[0] if isinstance(string, list) else str(string)
        elif isinstance(plugin_data, list) and plugin_data:
            return str(plugin_data[0])
        return ""
