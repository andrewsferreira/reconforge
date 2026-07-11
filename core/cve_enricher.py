"""Automatic CVE enrichment from finding content (E3)."""

from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import List


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_CPE_RE = re.compile(r"\bcpe:2\.3:[aho]:[^\s]+", re.IGNORECASE)


def enrich_references(description: str, evidence: str, references: List[str]) -> List[str]:
    """Append CVE/NVD links extracted from finding text.

    - Always links explicit CVE IDs found in description/evidence.
    - Optionally resolves CPE via NVD API when RECONFORGE_NVD_LOOKUP=1.
    """
    refs = list(references or [])
    text = f"{description}\n{evidence}"
    cves = {m.group(0).upper() for m in _CVE_RE.finditer(text)}
    for cve in sorted(cves):
        _add_unique(refs, f"https://nvd.nist.gov/vuln/detail/{cve}")

    if os.getenv("RECONFORGE_NVD_LOOKUP", "").strip() == "1":
        cpes = {m.group(0) for m in _CPE_RE.finditer(text)}
        for cpe in sorted(cpes):
            for cve in lookup_cves_for_cpe(cpe, limit=3):
                _add_unique(refs, f"https://nvd.nist.gov/vuln/detail/{cve}")

    return refs


def lookup_cves_for_cpe(cpe: str, limit: int = 3) -> List[str]:
    """Lookup CVEs for a given CPE via NVD API with local caching."""
    cache_path = Path.home() / ".reconforge" / "cve_cache.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache = _load_cache(cache_path)
    if cpe in cache:
        return cache[cpe][:limit]

    encoded = urllib.parse.quote(cpe, safe="")
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?cpeName={encoded}&resultsPerPage=5"
    )
    req = urllib.request.Request(url, headers={"User-Agent": "ReconForge/1.1.0"})
    cves: List[str] = []
    try:
        # url's scheme+host is the fixed literal above; only the
        # percent-encoded query string is variable.
        with urllib.request.urlopen(req, timeout=4) as resp:  # nosec B310
            data = json.loads(resp.read().decode("utf-8"))
            vulns = data.get("vulnerabilities", [])
            for item in vulns:
                cve = item.get("cve", {}).get("id")
                if isinstance(cve, str) and cve.upper().startswith("CVE-"):
                    cves.append(cve.upper())
    except Exception:
        return []

    cache[cpe] = cves
    cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    return cves[:limit]


def _load_cache(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _add_unique(refs: List[str], value: str) -> None:
    if value not in refs:
        refs.append(value)
