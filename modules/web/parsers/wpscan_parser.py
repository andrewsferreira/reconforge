"""ReconForge WPScan Parser - Parse WPScan JSON output.

Author: Andrews Ferreira

Extracts:
- WordPress version and security status
- Vulnerable plugins and themes
- Enumerated users
- Server and interesting findings
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class WpscanVuln:
    """A single WPScan vulnerability."""
    title: str = ""
    component: str = ""  # core, plugin name, theme name
    component_version: str = ""
    # Every construction site in this file passes severity= explicitly
    # via _classify_severity() (which only ever returns high/medium/low),
    # so this default is never actually used — "low" matches
    # _classify_severity()'s own fallback rather than implying "high" is
    # a safe/neutral default for an uncategorized vulnerability.
    severity: str = "low"
    references: list[str] = field(default_factory=list)
    fixed_in: str = ""


@dataclass
class WpscanResult:
    """Complete WPScan result."""
    wp_version: str = ""
    wp_status: str = ""  # latest, outdated, insecure
    plugins: dict[str, str] = field(default_factory=dict)  # name -> version
    themes: dict[str, str] = field(default_factory=dict)
    users: list[str] = field(default_factory=list)
    vulnerabilities: list[WpscanVuln] = field(default_factory=list)
    raw_output: str = ""

    @property
    def is_insecure(self) -> bool:
        return self.wp_status == "insecure"


class WpscanParser:
    """Parse WPScan JSON and text output into structured data."""
    HIGH_KW = (
        "rce", "sql", "xss", "csrf", "ssrf", "lfi", "rfi",
        "auth bypass", "authentication bypass",
    )
    MEDIUM_KW = ("enumeration", "information disclosure", "exposed", "debug")
    TEXT_NOISE_KW = (
        "no wpscan api token given",
        "the remote website is up",
        "started:",
        "finished:",
    )


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
                references = self._extract_references(vuln.get("references", {}))
                result.vulnerabilities.append(WpscanVuln(
                    title=vuln.get("title", "Unknown"),
                    component=name,
                    component_version=ver,
                    severity=self._classify_severity(vuln.get("title", "")),
                    references=references[:8],
                    fixed_in=vuln.get("fixed_in", ""),
                ))

        # Themes
        for name, tdata in data.get("themes", {}).items():
            ver = tdata.get("version", {}).get("number", "unknown")
            result.themes[name] = ver

            for vuln in tdata.get("vulnerabilities", []):
                references = self._extract_references(vuln.get("references", {}))
                result.vulnerabilities.append(WpscanVuln(
                    title=vuln.get("title", "Unknown"),
                    component=name,
                    component_version=ver,
                    severity=self._classify_severity(vuln.get("title", "")),
                    references=references[:8],
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
                    result.users.append(u.get("username") or u.get("id") or str(u))
        result.users = list(dict.fromkeys(result.users))

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
            ver_match = re.search(r"WordPress version\s+([0-9][\w\.\-]+)", line, re.IGNORECASE)
            if ver_match and not result.wp_version:
                result.wp_version = ver_match.group(1)
            if "[!]" in line:
                cleaned = line.replace("[!]", "").strip().lower()
                if any(noise in cleaned for noise in self.TEXT_NOISE_KW):
                    continue
                result.vulnerabilities.append(WpscanVuln(
                    title=line,
                    severity=self._classify_severity(line),
                ))

        return result

    def _classify_severity(self, title: str) -> str:
        t = title.lower()
        if any(kw in t for kw in self.HIGH_KW):
            return "high"
        if any(kw in t for kw in self.MEDIUM_KW):
            return "medium"
        return "low"

    @staticmethod
    def _extract_references(refs_data) -> list[str]:
        refs: list[str] = []
        if isinstance(refs_data, dict):
            for key, value in refs_data.items():
                if isinstance(value, str):
                    refs.append(value)
                elif isinstance(value, list):
                    refs.extend(str(v) for v in value)
                elif value:
                    refs.append(str(value))
                if key.lower() == "cve" and isinstance(value, list):
                    refs.extend(f"CVE-{v}" if not str(v).startswith("CVE-") else str(v) for v in value)
        elif isinstance(refs_data, list):
            refs.extend(str(v) for v in refs_data)
        elif isinstance(refs_data, str):
            refs.append(refs_data)
        return [r for r in dict.fromkeys(refs) if r]
