"""Phase 25 regression: PortScanningPhase._scan_host()'s stealth branch
gates on `self.opsec.check("nmap_syn_scan")` with no lower-noise fallback.
Before this phase, nmap_syn_scan was misclassified "medium" noise in
core/detection_map.py, which is_allowed() denies in stealth mode — so
`--opsec stealth` silently produced zero port-scan results, even though
the method's own downstream logic (skipping the noisier version scan
"if opsec_mode != stealth") was clearly written assuming stealth-mode SYN
scans do find ports. These tests use the real OpsecChecker (not a
permissive stub) to prove the fix at the exact boundary where the bug
lived.
"""

from types import SimpleNamespace

from core.findings_manager import FindingsManager
from core.opsec_checks import OpsecChecker
from modules.network.parsers.nmap_parser import NmapHost, NmapPort, NmapResult
from modules.network.phases.port_scanning import PortScanningPhase


def _make_phase(opsec_mode: str, nmap_result: NmapResult) -> PortScanningPhase:
    phase = PortScanningPhase.__new__(PortScanningPhase)
    phase.PHASE_NAME = "port_scanning"
    phase.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None,
                                    error=lambda *a, **k: None)
    phase.notes = SimpleNamespace(add_command_note=lambda *a, **k: None)
    phase.findings = FindingsManager()
    phase.loot = SimpleNamespace(add_service=lambda **k: None)
    phase.workflow = SimpleNamespace(add_step=lambda **k: None, record_result=lambda *a, **k: None,
                                      suggest_next=lambda **k: None,
                                      add_attack_path=lambda **k: None)
    phase.opsec = OpsecChecker(mode=opsec_mode)
    phase.tools_used = []
    phase.nmap = SimpleNamespace(
        syn_scan=lambda target, ports: SimpleNamespace(
            success=True, stdout="", stderr="", command="nmap"
        ),
        version_scan=lambda target, ports: SimpleNamespace(success=False),
        get_xml_path=lambda kind: __import__("pathlib").Path("/nonexistent.xml"),
    )
    phase.parser = SimpleNamespace(
        parse_text=lambda stdout: nmap_result,
        check_known_vulns=lambda host: [],
        check_weak_configs=lambda host: [],
        check_anonymous_access=lambda host: [],
    )
    return phase


def _open_port(port_num: int) -> NmapPort:
    return NmapPort(port=port_num, protocol="tcp", state="open", service="http")


def test_stealth_mode_no_longer_blocks_the_scan():
    """Old bug: nmap_syn_scan's noise misclassification meant _scan_host()
    always returned early with an empty host_result in stealth mode,
    never reaching the actual scan_func call below."""
    target_host = NmapHost(ip="10.0.0.1", ports=[_open_port(445)])
    nmap_result = NmapResult(hosts=[target_host])

    phase = _make_phase("stealth", nmap_result)
    host_result = phase._scan_host("10.0.0.1", opsec_mode="stealth")

    assert len(host_result["open_ports"]) == 1
    assert host_result["open_ports"][0]["port"] == 445


def test_normal_and_aggressive_modes_still_scan():
    for mode in ("normal", "aggressive"):
        target_host = NmapHost(ip="10.0.0.1", ports=[_open_port(22)])
        nmap_result = NmapResult(hosts=[target_host])

        phase = _make_phase(mode, nmap_result)
        host_result = phase._scan_host("10.0.0.1", opsec_mode=mode)

        assert len(host_result["open_ports"]) == 1
        assert host_result["open_ports"][0]["port"] == 22
