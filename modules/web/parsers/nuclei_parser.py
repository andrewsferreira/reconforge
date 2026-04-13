"""ReconForge Nuclei Parser - Parse Nuclei JSONL output.

Author: Andrews Ferreira

Extracts:
- Template-matched vulnerabilities
- Severity levels from template metadata
- Matched URLs and extracted data
- CVE references and remediation advice
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


@dataclass
class NucleiFinding:
    """A single Nuclei finding."""
    template_id: str = ""
    name: str = ""
    severity: str = "info"
    matched_at: str = ""
    extracted: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    remediation: str = ""
    raw_data: str = ""


@dataclass
class NucleiResult:
    """Complete Nuclei scan result."""
    findings: List[NucleiFinding] = field(default_factory=list)
    raw_output: str = ""

    @property
    def by_severity(self) -> Dict[str, List[NucleiFinding]]:
        groups: Dict[str, List[NucleiFinding]] = {}
        for f in self.findings:
            groups.setdefault(f.severity, []).append(f)
        return groups


SEVERITY_MAP = {
    "critical": "critical", "high": "high",
    "medium": "medium", "low": "low", "info": "info",
}


class NucleiParser:
    """Parse Nuclei JSONL output into structured data."""

    def parse_jsonl(self, jsonl_path: Path) -> NucleiResult:
        """Parse Nuclei JSONL output file.

        Args:
            jsonl_path: Path to Nuclei JSONL output.

        Returns:
            NucleiResult with parsed findings.
        """
        result = NucleiResult()

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

            info = entry.get("info", {})
            template_id = entry.get("template-id",
                                    entry.get("templateID", "unknown"))

            refs = info.get("reference", [])
            if isinstance(refs, str):
                refs = [refs]

            tags = info.get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            nuclei_sev = info.get("severity", "info").lower()

            finding = NucleiFinding(
                template_id=template_id,
                name=info.get("name", template_id),
                severity=SEVERITY_MAP.get(nuclei_sev, "info"),
                matched_at=entry.get("matched-at",
                                     entry.get("matched", "")),
                extracted=entry.get("extracted-results", [])[:10],
                references=refs[:5] if refs else [],
                tags=tags,
                remediation=info.get("remediation", ""),
                raw_data=json.dumps(entry, default=str)[:800],
            )
            result.findings.append(finding)

        return result
