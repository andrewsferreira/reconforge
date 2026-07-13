"""Phase 8-H: api/phases/discovery.py's ffuf-hit confidence must be tied
to HTTP status code, matching modules/web/phases/content_enumeration.py's
tiering for the same evidence type (an ffuf hit) — not unconditionally
"confirmed" regardless of status code.
"""

from types import SimpleNamespace

from core.findings_manager import FindingsManager
from modules.api.parsers.ffuf_parser import FfufApiEntry, FfufApiResult
from modules.api.phases.discovery import DiscoveryPhase


def _make_phase(entries):
    phase = DiscoveryPhase.__new__(DiscoveryPhase)
    phase.PHASE_NAME = "discovery"
    phase.logger = SimpleNamespace(warning=lambda *a, **k: None, info=lambda *a, **k: None)
    phase.tools_used = []
    phase.opsec = SimpleNamespace(check=lambda *_a, **_k: True)
    phase.findings = FindingsManager()
    phase.loot = SimpleNamespace(add=lambda **k: None)
    phase.notes = SimpleNamespace(add=lambda *a, **k: None)
    phase.ffuf = SimpleNamespace(
        is_available=lambda: True,
        endpoint_scan=lambda *a, **k: SimpleNamespace(success=True, stderr=""),
        get_json_path=lambda *a, **k: SimpleNamespace(),
    )
    phase.ffuf_parser = SimpleNamespace(
        parse_json=lambda path: FfufApiResult(entries=entries),
        classify_endpoint=lambda url: "normal",
    )
    return phase


def test_200_status_hit_gets_high_confidence():
    entries = [FfufApiEntry(url="http://target/api/users", status=200, length=100)]
    phase = _make_phase(entries)
    results = {"endpoints": []}

    phase._run_ffuf_scan("http://target/", "/wordlist", [], results)

    findings = phase.findings.get_all()
    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert findings[0].confidence != "confirmed"


def test_500_status_hit_gets_medium_confidence():
    entries = [FfufApiEntry(url="http://target/api/broken", status=500, length=50)]
    phase = _make_phase(entries)
    results = {"endpoints": []}

    phase._run_ffuf_scan("http://target/", "/wordlist", [], results)

    findings = phase.findings.get_all()
    assert len(findings) == 1
    assert findings[0].confidence == "medium"
