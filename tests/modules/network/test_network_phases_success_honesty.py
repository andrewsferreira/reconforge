"""Phase 27 regression: three network module phase files set
results["success"] = True unconditionally regardless of whether any tool
actually ran — the same "decorative success" bug class Phase 17 fixed
across AD/web/api and Phase 26 fixed for the surface module, but missed
here because Phase 17's audit claimed the network module was "already
correct" based on host_discovery.py's genuinely honest early-return
pattern, without checking port_scanning.py/authentication_checks.py/
service_enumeration.py's outer run() methods individually.

None of the network module's phase files populated the base class's
self.tools_used list before this phase either (permanently empty,
inherited unused since the module's creation) — now wired at each real
tool-invocation point and used as the honest success signal, matching
the established convention from Phase 17/25/26.
"""

from types import SimpleNamespace

from core.findings_manager import FindingsManager
from modules.network.phases.authentication_checks import AuthenticationChecksPhase
from modules.network.phases.port_scanning import PortScanningPhase
from modules.network.phases.service_enumeration import ServiceEnumerationPhase

# ── port_scanning.py ────────────────────────────────────────────────

def _make_port_scanning_phase() -> PortScanningPhase:
    phase = PortScanningPhase.__new__(PortScanningPhase)
    phase.PHASE_NAME = "port_scanning"
    phase.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None,
                                    error=lambda *a, **k: None)
    phase.notes = SimpleNamespace(add_command_note=lambda *a, **k: None,
                                   add_phase_start=lambda *a, **k: None,
                                   add_phase_end=lambda *a, **k: None)
    phase.findings = FindingsManager()
    phase.loot = SimpleNamespace(add_service=lambda **k: None)
    phase.workflow = SimpleNamespace(add_step=lambda **k: None, record_result=lambda *a, **k: None,
                                      suggest_next=lambda **k: None, add_attack_path=lambda **k: None)
    phase.tools_used = []
    phase.output_dir = __import__("pathlib").Path("/tmp")
    return phase


def test_port_scanning_success_false_when_no_targets(tmp_path, monkeypatch):
    phase = _make_port_scanning_phase()
    phase.output_dir = tmp_path
    phase.opsec = SimpleNamespace(check=lambda *a, **k: True)

    results = phase.run([], opsec_mode="normal")

    assert phase.tools_used == []
    assert results["success"] is False


def test_port_scanning_success_true_when_a_host_is_scanned(tmp_path):
    phase = _make_port_scanning_phase()
    phase.output_dir = tmp_path
    phase.opsec = SimpleNamespace(check=lambda *a, **k: True)
    phase.nmap = SimpleNamespace(
        syn_scan=lambda target, ports: SimpleNamespace(success=True, stdout="", stderr="", command="nmap"),
        get_xml_path=lambda kind: tmp_path / "nonexistent.xml",
    )
    phase.parser = SimpleNamespace(
        parse_text=lambda stdout: SimpleNamespace(live_hosts=[]),
        check_known_vulns=lambda host: [],
        check_weak_configs=lambda host: [],
        check_anonymous_access=lambda host: [],
    )

    results = phase.run(["10.0.0.1"], opsec_mode="normal")

    assert "nmap" in phase.tools_used
    assert results["success"] is True


# ── authentication_checks.py ────────────────────────────────────────

def _make_auth_checks_phase() -> AuthenticationChecksPhase:
    phase = AuthenticationChecksPhase.__new__(AuthenticationChecksPhase)
    phase.PHASE_NAME = "authentication_checks"
    phase.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None)
    phase.notes = SimpleNamespace(add=lambda *a, **k: None, add_phase_start=lambda *a, **k: None,
                                   add_phase_end=lambda *a, **k: None)
    phase.findings = FindingsManager()
    phase.loot = SimpleNamespace(add_credential=lambda **k: None)
    phase.workflow = SimpleNamespace(add_step=lambda **k: None, record_result=lambda *a, **k: None,
                                      add_attack_path=lambda **k: None)
    phase.tools_used = []
    return phase


def test_auth_checks_success_false_when_nothing_applicable(tmp_path):
    """No matching ports for anonymous testing, brute-force not opted in
    (the default) -> nothing was actually checked."""
    phase = _make_auth_checks_phase()
    phase.output_dir = tmp_path
    phase.smbclient = SimpleNamespace(is_available=lambda: True, null_session_test=lambda t: SimpleNamespace(success=True, stdout=""))

    results = phase.run("10.0.0.1", scan_results={"hosts": {"10.0.0.1": {"open_ports": [{"port": 8080}]}}})

    assert phase.tools_used == []
    assert results["success"] is False


def test_auth_checks_success_true_when_smb_null_session_tested(tmp_path):
    phase = _make_auth_checks_phase()
    phase.output_dir = tmp_path
    phase.smbclient = SimpleNamespace(
        is_available=lambda: True,
        null_session_test=lambda t: SimpleNamespace(success=True, stdout="NT_STATUS_ACCESS_DENIED"),
    )

    results = phase.run("10.0.0.1", scan_results={"hosts": {"10.0.0.1": {"open_ports": [{"port": 445}]}}})

    assert "smbclient" in phase.tools_used
    assert results["success"] is True


# ── service_enumeration.py ──────────────────────────────────────────

def _make_service_enum_phase() -> ServiceEnumerationPhase:
    phase = ServiceEnumerationPhase.__new__(ServiceEnumerationPhase)
    phase.PHASE_NAME = "service_enumeration"
    phase.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None)
    phase.notes = SimpleNamespace(add_command_note=lambda *a, **k: None, add_phase_start=lambda *a, **k: None,
                                   add_phase_end=lambda *a, **k: None)
    phase.findings = FindingsManager()
    phase.loot = SimpleNamespace(add=lambda **k: None, add_user=lambda **k: None, add_share=lambda **k: None)
    phase.workflow = SimpleNamespace(add_step=lambda **k: None, record_result=lambda *a, **k: None,
                                      add_attack_path=lambda **k: None)
    phase.opsec = SimpleNamespace(check=lambda *a, **k: True)
    phase.tools_used = []
    return phase


def test_service_enum_success_false_when_no_matching_ports(tmp_path):
    """No SMB (139/445) or LDAP (389/636) ports, and no other open ports
    to NSE-script-scan -> nothing was actually enumerated."""
    phase = _make_service_enum_phase()
    phase.output_dir = tmp_path

    results = phase.run("10.0.0.1", scan_results={"hosts": {"10.0.0.1": {"open_ports": []}}})

    assert phase.tools_used == []
    assert results["success"] is False


def test_service_enum_success_true_when_smb_enumerated(tmp_path):
    phase = _make_service_enum_phase()
    phase.output_dir = tmp_path
    phase.smbclient = SimpleNamespace(
        is_available=lambda: True,
        list_shares=lambda t: SimpleNamespace(success=False, stdout="", stderr=""),
        test_share_access=lambda t, name: SimpleNamespace(success=False, stdout=""),
    )
    phase.smb_parser = SimpleNamespace(
        parse_share_list=lambda stdout, target: SimpleNamespace(null_session=False, domain="", shares=[]),
        get_interesting_shares=lambda parsed: [],
    )
    phase.enum4linux = SimpleNamespace(is_available=lambda: False)
    phase.nmap = SimpleNamespace(
        smb_scripts=lambda t: SimpleNamespace(success=False, stdout="", stderr=""),
        get_xml_path=lambda kind: tmp_path / "nonexistent.xml",
    )
    phase.nmap_parser = SimpleNamespace()

    results = phase.run(
        "10.0.0.1", scan_results={"hosts": {"10.0.0.1": {"open_ports": [{"port": 445}]}}},
        opsec_mode="normal",
    )

    assert "smbclient" in phase.tools_used
    assert results["success"] is True
