"""Phase 25 regression: PortDiscoveryPhase.run() gates its entire scan on
`self.opsec.check("nmap_syn_scan")` with no lower-noise fallback. Before
this phase, nmap_syn_scan was misclassified "medium" noise in
core/detection_map.py, which is_allowed() denies in stealth mode — so
`--opsec stealth` silently produced zero port-discovery results, the one
mode an operator picks specifically to still get results while staying
quiet. These tests use the real OpsecChecker (not a permissive stub) to
prove the fix at the exact boundary where the bug lived.
"""

from pathlib import Path
from types import SimpleNamespace

from core.opsec_checks import OpsecChecker
from modules.surface.phases.port_discovery import PortDiscoveryPhase


def _make_phase(opsec_mode: str, tmp_path: Path) -> PortDiscoveryPhase:
    phase = PortDiscoveryPhase.__new__(PortDiscoveryPhase)
    phase.PHASE_NAME = "port_discovery"
    phase.logger = SimpleNamespace(
        info=lambda *a, **k: None, warning=lambda *a, **k: None, error=lambda *a, **k: None
    )
    phase.notes = SimpleNamespace(add=lambda *a, **k: None, add_command_note=lambda *a, **k: None)
    phase.loot = SimpleNamespace(add_service=lambda **k: None)
    phase.workflow = SimpleNamespace(add_step=lambda **k: None, record_result=lambda *a, **k: None)
    phase.opsec = OpsecChecker(mode=opsec_mode)
    phase.output_dir = tmp_path
    phase.tools_used = []
    phase.findings = SimpleNamespace(add=lambda **k: None)
    phase.nmap = SimpleNamespace(
        is_available=lambda: True,
        stealth_syn_scan=lambda target: SimpleNamespace(
            success=True, stdout="", stderr="", command="nmap -sS"
        ),
        get_xml_path=lambda kind: tmp_path / "nonexistent.xml",
    )
    phase.parser = SimpleNamespace(
        parse_nmap_xml=lambda path: SimpleNamespace(ports=[]),
        parse_nmap_text=lambda stdout: SimpleNamespace(ports=[]),
    )

    def _phase_output(filename: str) -> Path:
        return tmp_path / filename

    phase.phase_output = _phase_output
    return phase


def test_stealth_mode_no_longer_blocks_the_scan(tmp_path):
    """Old bug: nmap_syn_scan's noise misclassification meant this always
    returned early with results["success"] == False before ever calling
    nmap. Now the scan actually proceeds."""
    phase = _make_phase("stealth", tmp_path)

    results = phase.run("10.0.0.1")

    assert "nmap" in phase.tools_used
    assert results["success"] is True


def test_normal_and_aggressive_modes_still_scan(tmp_path):
    for mode in ("normal", "aggressive"):
        phase = _make_phase(mode, tmp_path)
        results = phase.run("10.0.0.1")
        assert "nmap" in phase.tools_used
        assert results["success"] is True
