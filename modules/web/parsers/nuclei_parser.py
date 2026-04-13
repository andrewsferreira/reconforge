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

from modules.web.parsers.severity import normalize_severity


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
            if not isinstance(entry, dict):
                continue

            info = entry.get("info", {})
            if not isinstance(info, dict):
                info = {}
            template_id = entry.get("template-id",
                                    entry.get("templateID", "unknown"))

            refs = info.get("reference", info.get("references", []))
            refs = self._as_list(refs)

            tags = info.get("tags", [])
            tags = self._as_list(tags, split_csv=True)

            nuclei_sev = normalize_severity(info.get("severity", "info"))
            extracted = self._as_list(entry.get("extracted-results", []))

            finding = NucleiFinding(
                template_id=template_id,
                name=info.get("name", template_id),
                severity=nuclei_sev,
                matched_at=entry.get("matched-at",
                                     entry.get("matched", "")),
                extracted=extracted[:10],
                references=refs[:5] if refs else [],
                tags=tags,
                remediation=info.get("remediation", ""),
                raw_data=json.dumps(entry, default=str)[:800],
            )
            result.findings.append(finding)

        return result

    @staticmethod
    def _as_list(value, split_csv: bool = False) -> List[str]:
        if value is None:
            return []
        if isinstance(value, list):
            items: List[str] = []
            for v in value:
                text = str(v).strip()
                if not text:
                    continue
                if split_csv and "," in text:
                    items.extend(part.strip() for part in text.split(",") if part.strip())
                else:
                    items.append(text)
            return items
        if isinstance(value, dict):
            items: List[str] = []
            for v in value.values():
                if isinstance(v, list):
                    items.extend(str(i).strip() for i in v if str(i).strip())
                elif v:
                    items.append(str(v).strip())
            return items
        if isinstance(value, str):
            if split_csv:
                return [v.strip() for v in value.split(",") if v.strip()]
            return [value.strip()] if value.strip() else []
        return [str(value).strip()] if str(value).strip() else []
