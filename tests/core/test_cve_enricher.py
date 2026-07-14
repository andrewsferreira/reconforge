import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.cve_enricher as cve_enricher
from core.cve_enricher import enrich_references


def test_enrich_references_extracts_cve_ids():
    refs = enrich_references(
        description="Potential issue CVE-2023-12345 detected",
        evidence="banner mentions CVE-2021-44228",
        references=[],
    )

    assert "https://nvd.nist.gov/vuln/detail/CVE-2023-12345" in refs
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in refs


# ── Phase 20-A: in-memory caching + rate limiting for lookup_cves_for_cpe ──

@pytest.fixture(autouse=True)
def _reset_module_state(tmp_path, monkeypatch):
    """FindingsManager.add() is called in tight loops throughout phase
    code, and each call can reach lookup_cves_for_cpe(). The module-level
    memory cache and rate-limit clock must not leak between tests."""
    monkeypatch.setattr(cve_enricher, "_MEMORY_CACHE", {})
    monkeypatch.setattr(cve_enricher, "_CACHE_LOADED", False)
    monkeypatch.setattr(cve_enricher, "_last_request_at", 0.0)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    yield


def _fake_urlopen(cves):
    class _Resp:
        def __enter__(self):
            body = json.dumps({
                "vulnerabilities": [{"cve": {"id": c}} for c in cves]
            }).encode("utf-8")
            return SimpleNamespace(read=lambda: body)

        def __exit__(self, *a):
            return False

    return lambda req, timeout=4: _Resp()


def test_lookup_cves_for_cpe_hits_network_once_then_uses_memory_cache(monkeypatch):
    """Phase 20-A regression: a second lookup for the same CPE within the
    same process must not re-read the on-disk cache file or hit the
    network again — the in-memory cache is checked first."""
    call_count = {"n": 0}

    def counting_urlopen(req, timeout=4):
        call_count["n"] += 1
        return _fake_urlopen(["CVE-2024-0001"])(req, timeout)

    monkeypatch.setattr(cve_enricher.urllib.request, "urlopen", counting_urlopen)
    monkeypatch.setattr(cve_enricher, "_MIN_REQUEST_INTERVAL_SECONDS", 0.0)

    first = cve_enricher.lookup_cves_for_cpe("cpe:2.3:a:apache:http_server:2.4.0")
    second = cve_enricher.lookup_cves_for_cpe("cpe:2.3:a:apache:http_server:2.4.0")

    assert first == ["CVE-2024-0001"]
    assert second == ["CVE-2024-0001"]
    assert call_count["n"] == 1


def test_lookup_cves_for_cpe_seeds_memory_cache_from_disk_without_network(tmp_path, monkeypatch):
    """A CPE already present in the on-disk cache from a prior run must
    not trigger a live network call at all."""
    cache_dir = tmp_path / ".reconforge"
    cache_dir.mkdir()
    (cache_dir / "cve_cache.json").write_text(
        json.dumps({"cpe:2.3:a:nginx:nginx:1.18.0": ["CVE-2021-23017"]})
    )

    def fail_if_called(req, timeout=4):
        raise AssertionError("must not hit the network for an already-cached CPE")

    monkeypatch.setattr(cve_enricher.urllib.request, "urlopen", fail_if_called)

    result = cve_enricher.lookup_cves_for_cpe("cpe:2.3:a:nginx:nginx:1.18.0")

    assert result == ["CVE-2021-23017"]


def test_lookup_cves_for_cpe_rate_limits_successive_live_requests(monkeypatch):
    """Phase 20-A regression: distinct CPEs (never cached) must not fire
    back-to-back live NVD requests with zero delay — a tight per-finding
    loop with many unique CPEs could otherwise hammer the NVD API."""
    monkeypatch.setattr(cve_enricher.urllib.request, "urlopen", _fake_urlopen(["CVE-2024-0002"]))
    monkeypatch.setattr(cve_enricher, "_MIN_REQUEST_INTERVAL_SECONDS", 6.0)

    sleep_calls = []
    monkeypatch.setattr(cve_enricher.time, "sleep", lambda s: sleep_calls.append(s))

    # First call: no prior request, so no sleep should be needed.
    cve_enricher.lookup_cves_for_cpe("cpe:2.3:a:vendor:product_a:1.0")
    assert sleep_calls == []

    # Second call for a *different*, never-cached CPE immediately after:
    # elapsed time is ~0s, well under the 6s minimum interval, so a sleep
    # must be enforced before the second live request fires.
    cve_enricher.lookup_cves_for_cpe("cpe:2.3:a:vendor:product_b:1.0")
    assert len(sleep_calls) == 1
    assert sleep_calls[0] > 0


def test_lookup_cves_for_cpe_network_failure_returns_empty_list(monkeypatch):
    def raising_urlopen(req, timeout=4):
        raise OSError("network unreachable")

    monkeypatch.setattr(cve_enricher.urllib.request, "urlopen", raising_urlopen)
    monkeypatch.setattr(cve_enricher, "_MIN_REQUEST_INTERVAL_SECONDS", 0.0)

    result = cve_enricher.lookup_cves_for_cpe("cpe:2.3:a:vendor:broken:1.0")

    assert result == []
