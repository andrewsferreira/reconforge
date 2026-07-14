"""Phase 26 regression: ServiceFingerprintPhase.run() set
results["success"] = True unconditionally, regardless of whether
_run_version_scan()/_run_http_probe() actually did anything. Both
sub-steps can no-op silently (nmap/httpx unavailable, opsec-blocked, no
candidate ports) without raising, so a run where zero tools executed
still reported success — the same "decorative success" bug class Phase
17 fixed across the AD/web/api modules. Phase 17's own audit claimed the
surface module was "already correct", which held for port_discovery.py
(a real early-return before success=True) but not for this file.
"""

from pathlib import Path
from types import SimpleNamespace

from core.opsec_checks import OpsecChecker
from modules.surface.phases.service_fingerprint import ServiceFingerprintPhase


def _make_phase(tmp_path: Path, *, nmap_available: bool, httpx_available: bool) -> ServiceFingerprintPhase:
    phase = ServiceFingerprintPhase.__new__(ServiceFingerprintPhase)
    phase.PHASE_NAME = "service_fingerprint"
    phase.logger = SimpleNamespace(
        info=lambda *a, **k: None, warning=lambda *a, **k: None, error=lambda *a, **k: None
    )
    phase.notes = SimpleNamespace(add=lambda *a, **k: None, add_command_note=lambda *a, **k: None)
    phase.loot = SimpleNamespace(add_service=lambda **k: None)
    phase.workflow = SimpleNamespace(add_step=lambda **k: None, record_result=lambda *a, **k: None)
    phase.opsec = OpsecChecker(mode="aggressive")
    phase.output_dir = tmp_path
    phase.tools_used = []
    phase.findings = SimpleNamespace(add=lambda **k: None)
    phase.nmap = SimpleNamespace(
        is_available=lambda: nmap_available,
        service_version_scan=lambda target, ports: SimpleNamespace(
            success=True, stdout="", stderr="", command="nmap -sV"
        ),
        get_xml_path=lambda kind: tmp_path / "nonexistent.xml",
    )
    phase.detector = SimpleNamespace(
        is_available=lambda: httpx_available,
        probe_services=lambda target, ports: SimpleNamespace(
            success=True, stdout="", stderr="", command="httpx"
        ),
        get_output_path=lambda: tmp_path / "httpx.json",
    )
    phase.parser = SimpleNamespace(
        parse_nmap_xml=lambda path: SimpleNamespace(ports=[]),
        parse_httpx_json=lambda path: SimpleNamespace(services=[]),
    )

    def _phase_output(filename: str) -> Path:
        return tmp_path / filename

    phase.phase_output = _phase_output
    return phase


def test_success_is_false_when_no_tool_ever_runs(tmp_path):
    """Old bug: this returned success=True even though neither nmap nor
    httpx were available and no work happened at all."""
    phase = _make_phase(tmp_path, nmap_available=False, httpx_available=False)

    results = phase.run("10.0.0.1", ports=[{"port": 80, "service": "http"}])

    assert phase.tools_used == []
    assert results["success"] is False


def test_success_is_false_when_no_candidate_ports(tmp_path):
    """Both sub-steps no-op on empty ports/no HTTP-looking ports."""
    phase = _make_phase(tmp_path, nmap_available=True, httpx_available=True)

    results = phase.run("10.0.0.1", ports=[])

    assert phase.tools_used == []
    assert results["success"] is False


def test_success_is_true_when_nmap_runs(tmp_path):
    phase = _make_phase(tmp_path, nmap_available=True, httpx_available=False)

    results = phase.run("10.0.0.1", ports=[{"port": 22, "service": "ssh"}])

    assert "nmap" in phase.tools_used
    assert results["success"] is True


def test_success_is_true_when_httpx_runs(tmp_path):
    phase = _make_phase(tmp_path, nmap_available=False, httpx_available=True)

    results = phase.run("10.0.0.1", ports=[{"port": 80, "service": "http"}])

    assert "httpx" in phase.tools_used
    assert results["success"] is True
