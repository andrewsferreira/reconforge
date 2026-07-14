"""Phase 9-A: AuthenticationChecksPhase must not report SMB null-session
access twice for a host with both port 139 and 445 open — the underlying
smbclient.null_session_test() is host-level (ignores port), but
ANON_TEST_SERVICES previously mapped both ports to the same test, causing
it to run (and record a finding) once per matching port.
"""

from types import SimpleNamespace

from core.findings_manager import FindingsManager
from modules.network.phases.authentication_checks import AuthenticationChecksPhase


def _make_phase() -> AuthenticationChecksPhase:
    phase = AuthenticationChecksPhase.__new__(AuthenticationChecksPhase)
    phase.PHASE_NAME = "authentication_checks"
    phase.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None)
    phase.findings = FindingsManager()
    phase.workflow = SimpleNamespace(add_step=lambda **k: None, record_result=lambda *a, **k: None,
                                      suggest_next=lambda **k: None)
    phase.smbclient = SimpleNamespace(
        is_available=lambda: True,
        null_session_test=lambda target: SimpleNamespace(success=True, stdout="Sharename Type Comment"),
    )
    phase.tools_used = []
    return phase


def test_dual_port_smb_host_produces_one_finding_not_two():
    phase = _make_phase()
    results = {"anonymous_access": [], "weak_auth": []}
    open_ports = [{"port": 139}, {"port": 445}]

    phase._check_anonymous_access("10.10.10.1", [139, 445], open_ports, results)

    findings = phase.findings.get_all()
    smb_findings = [f for f in findings if "null session" in f.description.lower()]
    assert len(smb_findings) == 1
    assert len(results["anonymous_access"]) == 1


def test_finding_target_is_host_not_port_specific():
    """The old code used target=f'{target}:{port_num}', implying the
    condition was specific to one port, when the underlying test is
    host-level."""
    phase = _make_phase()
    results = {"anonymous_access": [], "weak_auth": []}
    open_ports = [{"port": 139}, {"port": 445}]

    phase._check_anonymous_access("10.10.10.1", [139, 445], open_ports, results)

    findings = phase.findings.get_all()
    assert findings[0].target == "10.10.10.1"


def test_single_smb_port_still_reports_finding():
    phase = _make_phase()
    results = {"anonymous_access": [], "weak_auth": []}
    open_ports = [{"port": 445}]

    phase._check_anonymous_access("10.10.10.1", [445], open_ports, results)

    findings = phase.findings.get_all()
    assert len(findings) == 1
