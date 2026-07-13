"""ReconForge Nikto Parser - Parse Nikto JSON and text output.

Author: Andrews Ferreira

Extracts:
- Vulnerability findings with OSVDB references
- Server misconfigurations
- Outdated software detections
- Severity classification based on description keywords
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class NiktoFinding:
    """A single Nikto finding."""
    description: str = ""
    osvdb_id: str = ""
    method: str = "GET"
    uri: str = ""
    severity: str = "info"
    raw_data: str = ""


@dataclass
class NiktoResult:
    """Complete Nikto scan result."""
    findings: List[NiktoFinding] = field(default_factory=list)
    target_ip: str = ""
    target_port: str = ""
    target_hostname: str = ""
    raw_output: str = ""


class NiktoParser:
    """Parse Nikto JSON and text output into structured data."""

    # Severity keyword mapping
    CRITICAL_KW = ("rce", "remote code", "injection", "backdoor", "command execution")
    HIGH_KW = ("xss", "sql", "lfi", "rfi", "traversal", "exec", "arbitrary",
               "upload", "deserialization")
    MEDIUM_KW = ("disclosure", "directory listing", "default", "backup",
                 "exposed", "sensitive", "configuration")
    LOW_KW = ("header", "cookie", "version", "uncommon", "deprecated")
    NOISE_PREFIXES = (
        "nikto v", "target ip:", "target hostname:", "target port:",
        "start time:", "end time:", "retrieved x-powered-by header:",
        "server:", "allowed http methods:", "root page / redirects to:",
        "no cgi directories found", "1 host(s) tested",
    )

    def parse_json(self, json_path: Path) -> NiktoResult:
        """Parse Nikto JSON output file.

        Args:
            json_path: Path to Nikto JSON output.

        Returns:
            NiktoResult with parsed findings.
        """
        result = NiktoResult()

        if not json_path.is_file():
            return result

        try:
            raw = json_path.read_text(encoding="utf-8", errors="replace")
            result.raw_output = raw
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            return result

        vulns = self._extract_vulns(data)

        for vuln in vulns:
            desc = vuln.get("msg", vuln.get("description", str(vuln)))
            finding = NiktoFinding(
                description=desc,
                osvdb_id=str(vuln.get("id", vuln.get("OSVDB", ""))),
                method=vuln.get("method", "GET"),
                uri=vuln.get("url", vuln.get("uri", "")),
                severity=self.classify_severity(desc),
                raw_data=json.dumps(vuln, default=str)[:500],
            )
            result.findings.append(finding)

        return result

    def parse_text(self, text: str) -> NiktoResult:
        """Parse Nikto plain-text output (fallback).

        Args:
            text: Nikto stdout text.

        Returns:
            NiktoResult with parsed findings.
        """
        result = NiktoResult(raw_output=text)

        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("- target ip:"):
                result.target_ip = line.split(":", 1)[1].strip()
                continue
            if line.lower().startswith("- target hostname:"):
                result.target_hostname = line.split(":", 1)[1].strip()
                continue
            if line.lower().startswith("- target port:"):
                result.target_port = line.split(":", 1)[1].strip()
                continue

            if not line.startswith("+ "):
                continue

            desc = line[2:].strip()
            if self._is_noise_line(desc):
                continue

            osvdb_id = ""
            osvdb_match = re.match(r"OSVDB-(\d+):\s*(.+)$", desc, flags=re.IGNORECASE)
            if osvdb_match:
                osvdb_id = osvdb_match.group(1)
                desc = osvdb_match.group(2).strip()

            result.findings.append(NiktoFinding(
                description=desc,
                osvdb_id=osvdb_id,
                severity=self.classify_severity(desc),
            ))

        return result

    def classify_severity(self, desc: str) -> str:
        """Classify finding severity based on description keywords."""
        desc_lower = desc.lower()
        if any(kw in desc_lower for kw in self.CRITICAL_KW):
            return "critical"
        if any(kw in desc_lower for kw in self.HIGH_KW):
            return "high"
        if any(kw in desc_lower for kw in self.MEDIUM_KW):
            return "medium"
        if any(kw in desc_lower for kw in self.LOW_KW):
            return "low"
        return "info"

    @staticmethod
    def _extract_vulns(data) -> list:
        """Extract vulnerability entries from various Nikto JSON formats."""
        vulns = []
        if isinstance(data, dict):
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                for host_data in data.values():
                    if isinstance(host_data, dict):
                        vulns.extend(host_data.get("vulnerabilities", []))
                        vulns.extend(host_data.get("items", []))
        elif isinstance(data, list):
            vulns = data
        return vulns

    def _is_noise_line(self, desc: str) -> bool:
        desc_lower = desc.lower()
        return any(desc_lower.startswith(prefix) for prefix in self.NOISE_PREFIXES)
