"""ReconForge API Nuclei Parser - Parse Nuclei JSONL output for API vulns.

Author: Andrews Ferreira

Extracts:
- Template-matched API vulnerabilities
- Severity levels from template metadata
- Matched URLs and extracted data
- CVE references and remediation advice
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from modules.web.parsers.severity import normalize_severity


@dataclass
class NucleiApiFinding:
    """A single Nuclei API finding."""
    template_id: str = ""
    name: str = ""
    severity: str = "info"
    matched_at: str = ""
    extracted: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    remediation: str = ""
    raw_data: str = ""
    matcher_name: str = ""
    curl_command: str = ""


@dataclass
class NucleiApiResult:
    """Complete Nuclei API scan result."""
    findings: list[NucleiApiFinding] = field(default_factory=list)
    raw_output: str = ""

    @property
    def by_severity(self) -> dict[str, list[NucleiApiFinding]]:
        groups: dict[str, list[NucleiApiFinding]] = {}
        for f in self.findings:
            groups.setdefault(f.severity, []).append(f)
        return groups

    @property
    def api_specific(self) -> list[NucleiApiFinding]:
        """Return only API-specific findings."""
        api_tags = {"api", "graphql", "swagger", "openapi", "jwt",
                    "oauth", "idor", "bola", "token", "rest"}
        return [
            f for f in self.findings
            if any(t in api_tags for t in f.tags)
        ]


class NucleiApiParser:
    """Parse Nuclei JSONL output for API vulnerability findings."""

    def parse_jsonl(self, jsonl_path: Path) -> NucleiApiResult:
        """Parse Nuclei JSONL output file.

        Args:
            jsonl_path: Path to Nuclei JSONL output.

        Returns:
            NucleiApiResult with parsed findings.
        """
        result = NucleiApiResult()

        if not jsonl_path.is_file():
            return result

        raw = jsonl_path.read_text(encoding="utf-8", errors="replace")
        result.raw_output = raw

        for line in raw.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue

            info = entry.get("info", {})
            if not isinstance(info, dict):
                info = {}
            template_id = entry.get("template-id") or entry.get("templateID") or "unknown"

            refs = info.get("reference", [])
            if isinstance(refs, str):
                refs = [refs]

            tags = info.get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            finding = NucleiApiFinding(
                template_id=template_id,
                name=info.get("name") or template_id,
                severity=normalize_severity(info.get("severity")),
                matched_at=entry.get("matched-at") or entry.get("matched") or "",
                extracted=entry.get("extracted-results", [])[:10],
                references=refs[:5] if refs else [],
                tags=tags,
                remediation=info.get("remediation", ""),
                matcher_name=entry.get("matcher-name", ""),
                curl_command=entry.get("curl-command", ""),
                raw_data=json.dumps(entry, default=str)[:800],
            )
            result.findings.append(finding)

        return result
