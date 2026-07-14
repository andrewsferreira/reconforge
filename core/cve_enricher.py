"""Automatic CVE enrichment from finding content (E3)."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import List


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_CPE_RE = re.compile(r"\bcpe:2\.3:[aho]:[^\s]+", re.IGNORECASE)

# FindingsManager.add() is called in tight per-share/per-user/per-port
# loops throughout phase code, and enrich_references() (which can trigger
# lookup_cves_for_cpe()) runs on every call. Without these two guards, an
# engagement with many findings that each embed a *different* CPE string
# would fire one blocking 4s-timeout NVD request per unique CPE with zero
# rate-limiting — slow, and a real risk of the NVD API rate-limiting or
# blocking the operator's IP.
#
# In-memory cache: avoids re-reading/re-writing the on-disk cache file on
# every call within a single process run — the file is only the
# cross-run persistence layer, not the per-run fast path.
_MEMORY_CACHE: dict = {}
_CACHE_LOADED = False

# Rate limit: NVD's public API (no API key) is documented as ~5 requests
# per rolling 30-second window; 6 seconds between requests keeps every
# call safely under that ceiling rather than bursting up to the edge.
_MIN_REQUEST_INTERVAL_SECONDS = 6.0
_last_request_at: float = 0.0


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
    """Lookup CVEs for a given CPE via NVD API with local caching.

    Cache reads/writes hit the in-memory `_MEMORY_CACHE` after the first
    call in a process (lazily seeded from the on-disk cache once); only a
    genuine cache miss reaches the network, and live requests are
    rate-limited to `_MIN_REQUEST_INTERVAL_SECONDS` apart.
    """
    global _CACHE_LOADED, _last_request_at

    cache_path = Path.home() / ".reconforge" / "cve_cache.json"

    if not _CACHE_LOADED:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        _MEMORY_CACHE.update(_load_cache(cache_path))
        _CACHE_LOADED = True

    if cpe in _MEMORY_CACHE:
        return _MEMORY_CACHE[cpe][:limit]

    elapsed = time.monotonic() - _last_request_at
    if elapsed < _MIN_REQUEST_INTERVAL_SECONDS:
        time.sleep(_MIN_REQUEST_INTERVAL_SECONDS - elapsed)

    encoded = urllib.parse.quote(cpe, safe="")
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?cpeName={encoded}&resultsPerPage=5"
    )
    req = urllib.request.Request(url, headers={"User-Agent": "ReconForge/1.1.0"})
    cves: List[str] = []
    try:
        _last_request_at = time.monotonic()
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

    _MEMORY_CACHE[cpe] = cves
    cache_path.write_text(json.dumps(_MEMORY_CACHE, indent=2), encoding="utf-8")
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
