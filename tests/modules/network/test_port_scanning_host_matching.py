"""Phase 19-A: PortScanningPhase._scan_host()'s host-matching loop used
`if host.ip == target or not host_result["open_ports"]:` — the second
clause means "no ports found yet" (true for every host until the first
match), not "no matching host found". If nmap's XML listed the target's
own (fully-filtered, zero-open-port) entry first, the loop kept going and
processed a second, unrelated host entry into the same host_result,
misattributing its ports/services/findings to the scanned target.
"""

from types import SimpleNamespace

from core.findings_manager import FindingsManager
from modules.network.parsers.nmap_parser import NmapHost, NmapPort, NmapResult
from modules.network.phases.port_scanning import PortScanningPhase


def _make_phase(nmap_result: NmapResult) -> PortScanningPhase:
    phase = PortScanningPhase.__new__(PortScanningPhase)
    phase.PHASE_NAME = "port_scanning"
    phase.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None,
                                    error=lambda *a, **k: None)
    phase.notes = SimpleNamespace(add_command_note=lambda *a, **k: None)
    phase.findings = FindingsManager()
    phase.loot = SimpleNamespace(add_service=lambda **k: None)
    phase.workflow = SimpleNamespace(add_step=lambda **k: None, record_result=lambda *a, **k: None,
                                      suggest_next=lambda **k: None)
    phase.opsec = SimpleNamespace(check=lambda *a, **k: True)
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


def test_scan_host_does_not_misattribute_unrelated_host_when_target_has_no_ports():
    """Old bug: target's own zero-port entry listed first, unrelated
    host's ports get processed into target's host_result anyway."""
    unrelated_host = NmapHost(ip="10.0.0.99", ports=[_open_port(8080)])
    target_host = NmapHost(ip="10.0.0.1", ports=[])  # target itself: no open ports
    nmap_result = NmapResult(hosts=[target_host, unrelated_host])

    phase = _make_phase(nmap_result)
    host_result = phase._scan_host("10.0.0.1", opsec_mode="normal")

    assert host_result["open_ports"] == []
    assert host_result["services"] == []


def test_scan_host_processes_matching_host_by_ip():
    matched = NmapHost(ip="10.0.0.1", ports=[_open_port(443)])
    other = NmapHost(ip="10.0.0.2", ports=[_open_port(22)])
    nmap_result = NmapResult(hosts=[other, matched])

    phase = _make_phase(nmap_result)
    host_result = phase._scan_host("10.0.0.1", opsec_mode="normal")

    assert len(host_result["open_ports"]) == 1
    assert host_result["open_ports"][0]["port"] == 443


def test_scan_host_falls_back_to_sole_host_entry_when_ip_does_not_match():
    """nmap may report a genuine single-target scan under a different
    identifier (e.g. hostname) — the sole entry should still be used."""
    sole_host = NmapHost(ip="target.internal", ports=[_open_port(80)])
    nmap_result = NmapResult(hosts=[sole_host])

    phase = _make_phase(nmap_result)
    host_result = phase._scan_host("10.0.0.1", opsec_mode="normal")

    assert len(host_result["open_ports"]) == 1
    assert host_result["open_ports"][0]["port"] == 80
