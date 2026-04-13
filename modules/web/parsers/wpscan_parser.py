"""ReconForge WPScan Parser - Parse WPScan JSON output.

Author: Andrews Ferreira

Extracts:
- WordPress version and security status
- Vulnerable plugins and themes
- Enumerated users
- Server and interesting findings
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


@dataclass
class WpscanVuln:
    """A single WPScan vulnerability."""
    title: str = ""
    component: str = ""  # core, plugin name, theme name
    component_version: str = ""
    severity: str = "high"
    references: List[str] = field(default_factory=list)
    fixed_in: str = ""


@dataclass
class WpscanResult:
    """Complete WPScan result."""
    wp_version: str = ""
    wp_status: str = ""  # latest, outdated, insecure
    plugins: Dict[str, str] = field(default_factory=dict)  # name -> version
    themes: Dict[str, str] = field(default_factory=dict)
    users: List[str] = field(default_factory=list)
    vulnerabilities: List[WpscanVuln] = field(default_factory=list)
    raw_output: str = ""

    @property
    def is_insecure(self) -> bool:
        return self.wp_status == "insecure"


class WpscanParser:
    """Parse WPScan JSON and text output into structured data."""

    def parse_json(self, json_path: Path) -> WpscanResult:
        """Parse WPScan JSON output file.

        Args:
            json_path: Path to WPScan JSON output.

        Returns:
            WpscanResult with parsed data.
        """
        result = WpscanResult()

        if not json_path.is_file():
            return result

        try:
            raw = json_path.read_text(encoding="utf-8")
            result.raw_output = raw
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            return result

        # WordPress version
        wp_ver = data.get("version", {})
        if wp_ver:
            result.wp_version = wp_ver.get("number", "unknown")
            result.wp_status = wp_ver.get("status", "")

        # Plugins
        for name, pdata in data.get("plugins", {}).items():
            ver = pdata.get("version", {}).get("number", "unknown")
            result.plugins[name] = ver

            for vuln in pdata.get("vulnerabilities", []):
                refs_data = vuln.get("references", {})
                ref_urls = refs_data.get("url", [])
                result.vulnerabilities.append(WpscanVuln(
                    title=vuln.get("title", "Unknown"),
                    component=name,
                    component_version=ver,
                    severity="high",
                    references=ref_urls[:5],
                    fixed_in=vuln.get("fixed_in", ""),
                ))

        # Themes
        for name, tdata in data.get("themes", {}).items():
            ver = tdata.get("version", {}).get("number", "unknown")
            result.themes[name] = ver

            for vuln in tdata.get("vulnerabilities", []):
                refs_data = vuln.get("references", {})
                ref_urls = refs_data.get("url", [])
                result.vulnerabilities.append(WpscanVuln(
                    title=vuln.get("title", "Unknown"),
                    component=name,
                    component_version=ver,
                    severity="high",
                    references=ref_urls[:5],
                    fixed_in=vuln.get("fixed_in", ""),
                ))

        # Users
        users_data = data.get("users", {})
        if isinstance(users_data, dict):
            result.users = list(users_data.keys())
        elif isinstance(users_data, list):
            for u in users_data:
                if isinstance(u, str):
                    result.users.append(u)
                elif isinstance(u, dict):
                    result.users.append(u.get("username", str(u)))

        return result

    def parse_text(self, text: str) -> WpscanResult:
        """Parse WPScan text output (fallback).

        Args:
            text: WPScan stdout text.

        Returns:
            WpscanResult with parsed data.
        """
        result = WpscanResult(raw_output=text)

        for line in text.splitlines():
            line = line.strip()
            if "[!]" in line:
                result.vulnerabilities.append(WpscanVuln(
                    title=line,
                    severity="medium",
                ))

        return result
