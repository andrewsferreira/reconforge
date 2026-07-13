"""Phase 17: surface_discovery.py, content_enumeration.py,
exploit_candidates.py, and vulnerability_scanning.py hardcoded
results["success"] = True unconditionally, regardless of whether any
underlying tool (whatweb/wafw00f/curl, ffuf/gobuster, wpscan/sqlmap,
nikto/nuclei) actually ran. Each phase's own "no findings" filler finding
masked this: it always fires when finding_count==0, so a target where
every tool was unavailable or OPSEC-blocked still reported success=True
with a synthetic "no issues found" finding. Fixed by gating success on
self.tools_used, which is only appended to once a tool actually executes
past its availability/OPSEC checks.
"""

from types import SimpleNamespace

from core.findings_manager import FindingsManager
from modules.web.phases.surface_discovery import SurfaceDiscoveryPhase
from modules.web.phases.content_enumeration import ContentEnumerationPhase
from modules.web.phases.exploit_candidates import ExploitCandidatesPhase
from modules.web.phases.vulnerability_scanning import VulnerabilityScanningPhase


def _base_stubs(phase, phase_name: str, tmp_path) -> None:
    phase.PHASE_NAME = phase_name
    phase.output_dir = tmp_path
    phase.logger = SimpleNamespace(
        info=lambda *a, **k: None, warning=lambda *a, **k: None,
        finding=lambda *a, **k: None,
    )
    phase.notes = SimpleNamespace(
        add=lambda *a, **k: None, add_command_note=lambda *a, **k: None,
        add_finding_note=lambda *a, **k: None,
    )
    phase.findings = FindingsManager()
    phase.loot = SimpleNamespace(add=lambda **k: None, add_service=lambda **k: None, add_user=lambda **k: None)
    phase.workflow = SimpleNamespace(
        add_step=lambda **k: None, record_result=lambda *a, **k: None,
        add_attack_path=lambda **k: None, suggest_next=lambda **k: None,
        add_rabbit_hole=lambda *a, **k: None,
    )
    phase.opsec = SimpleNamespace(check=lambda *a, **k: True)
    phase.tools_used = []


def _unavailable_tool():
    return SimpleNamespace(is_available=lambda: False)


def test_surface_discovery_reports_failure_when_all_tools_unavailable(tmp_path):
    phase = SurfaceDiscoveryPhase.__new__(SurfaceDiscoveryPhase)
    _base_stubs(phase, "surface_discovery", tmp_path)
    phase.whatweb = _unavailable_tool()
    phase.wafw00f = _unavailable_tool()
    phase.curl = _unavailable_tool()
    phase.whatweb_parser = SimpleNamespace()
    phase.wafw00f_parser = SimpleNamespace()

    results = phase.run("https://target.local")

    assert results["success"] is False
    assert phase.tools_used == []


def test_surface_discovery_reports_success_when_whatweb_runs(tmp_path):
    phase = SurfaceDiscoveryPhase.__new__(SurfaceDiscoveryPhase)
    _base_stubs(phase, "surface_discovery", tmp_path)
    phase.whatweb = SimpleNamespace(
        is_available=lambda: True,
        scan=lambda url: SimpleNamespace(success=True, stdout="", stderr=""),
        get_json_path=lambda: tmp_path / "whatweb.json",
    )
    phase.whatweb_parser = SimpleNamespace(
        parse_json=lambda path: SimpleNamespace(technologies=[]),
        parse_text=lambda text: SimpleNamespace(technologies=[]),
    )
    phase.wafw00f = _unavailable_tool()
    phase.wafw00f_parser = SimpleNamespace()
    phase.curl = _unavailable_tool()

    results = phase.run("https://target.local")

    assert results["success"] is True
    assert phase.tools_used == ["whatweb"]


def test_content_enumeration_reports_failure_when_all_tools_unavailable(tmp_path):
    phase = ContentEnumerationPhase.__new__(ContentEnumerationPhase)
    _base_stubs(phase, "content_enumeration", tmp_path)
    phase.ffuf = _unavailable_tool()
    phase.gobuster = _unavailable_tool()
    phase.ffuf_parser = SimpleNamespace()
    phase.gobuster_parser = SimpleNamespace()

    results = phase.run("https://target.local")

    assert results["success"] is False
    assert phase.tools_used == []
    # The synthetic "no notable paths" filler still fires — confirms the
    # old bug (finding_count-based gating) would have masked this.
    assert results["finding_count"] == 1


def test_content_enumeration_reports_success_when_ffuf_runs(tmp_path):
    phase = ContentEnumerationPhase.__new__(ContentEnumerationPhase)
    _base_stubs(phase, "content_enumeration", tmp_path)
    phase.resolve_wordlist = lambda *a, **k: "/tmp/wordlist.txt"
    phase.ffuf = SimpleNamespace(
        is_available=lambda: True,
        dir_scan=lambda url, wordlist: SimpleNamespace(success=True, stderr=""),
        get_json_path=lambda kind: tmp_path / "ffuf.json",
    )
    phase.ffuf_parser = SimpleNamespace(
        parse_json=lambda path: SimpleNamespace(entries=[]),
        status_to_severity=lambda status: "info",
        status_recommendation=lambda status: "",
    )
    phase.gobuster = _unavailable_tool()
    phase.gobuster_parser = SimpleNamespace()

    results = phase.run("https://target.local")

    assert results["success"] is True
    assert phase.tools_used == ["ffuf"]


def test_exploit_candidates_reports_failure_when_all_tools_unavailable(tmp_path):
    phase = ExploitCandidatesPhase.__new__(ExploitCandidatesPhase)
    _base_stubs(phase, "exploit_candidates", tmp_path)
    phase.wpscan = _unavailable_tool()
    phase.sqlmap = _unavailable_tool()
    phase.wpscan_parser = SimpleNamespace()

    results = phase.run("https://target.local", opt_in=True)

    assert results["success"] is False
    assert phase.tools_used == []


def test_exploit_candidates_reports_success_when_sqlmap_runs(tmp_path):
    phase = ExploitCandidatesPhase.__new__(ExploitCandidatesPhase)
    _base_stubs(phase, "exploit_candidates", tmp_path)
    phase.wpscan = _unavailable_tool()
    phase.wpscan_parser = SimpleNamespace()
    phase.sqlmap = SimpleNamespace(
        is_available=lambda: True,
        scan=lambda url: SimpleNamespace(stdout="target does not appear to be injectable"),
    )

    results = phase.run("https://target.local", opt_in=True)

    assert results["success"] is True
    assert phase.tools_used == ["sqlmap"]


def test_exploit_candidates_opt_out_is_still_success():
    """opt_in=False is a deliberate skip, not a failure — success=True here is honest."""
    phase = ExploitCandidatesPhase.__new__(ExploitCandidatesPhase)
    phase.PHASE_NAME = "exploit_candidates"
    phase.logger = SimpleNamespace(warning=lambda *a, **k: None)
    phase.notes = SimpleNamespace(add=lambda *a, **k: None)
    phase.findings = FindingsManager()

    results = phase.run("https://target.local", opt_in=False)

    assert results["success"] is True


def test_vulnerability_scanning_reports_failure_when_all_tools_unavailable(tmp_path):
    phase = VulnerabilityScanningPhase.__new__(VulnerabilityScanningPhase)
    _base_stubs(phase, "vulnerability_scanning", tmp_path)
    phase.nikto = _unavailable_tool()
    phase.nuclei = _unavailable_tool()
    phase.nikto_parser = SimpleNamespace()
    phase.nuclei_parser = SimpleNamespace()
    phase.runner = SimpleNamespace(check_tool=lambda name: False)

    results = phase.run("https://target.local")

    assert results["success"] is False
    assert phase.tools_used == []


def test_vulnerability_scanning_reports_success_when_nikto_runs(tmp_path):
    phase = VulnerabilityScanningPhase.__new__(VulnerabilityScanningPhase)
    _base_stubs(phase, "vulnerability_scanning", tmp_path)
    phase.nikto = SimpleNamespace(
        is_available=lambda: True,
        scan=lambda url: SimpleNamespace(success=True, stdout="", stderr=""),
        get_json_path=lambda: tmp_path / "nikto.json",
    )
    phase.nikto_parser = SimpleNamespace(
        parse_json=lambda path: SimpleNamespace(findings=[]),
        parse_text=lambda text: SimpleNamespace(findings=[]),
    )
    phase.nuclei = _unavailable_tool()
    phase.nuclei_parser = SimpleNamespace()
    phase.runner = SimpleNamespace(check_tool=lambda name: False)

    results = phase.run("https://target.local")

    assert results["success"] is True
    assert phase.tools_used == ["nikto"]
