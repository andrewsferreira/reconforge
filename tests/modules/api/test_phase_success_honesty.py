"""Phase 17: discovery.py, authentication.py, authorization.py, and
fuzzing.py hardcoded results["success"] = True unconditionally, regardless
of whether any underlying tool (httpx/ffuf, nuclei, arjun) actually ran or
any input data (spec_data, auth_token, endpoints, discovered_params) was
available to analyze. Fixed by gating success on self.tools_used (only
appended to once a tool actually executes past its availability/OPSEC
checks) plus, for authentication/authorization, whether real input data
was available for pure analysis paths that need no tool call at all.
"""

from types import SimpleNamespace

from core.findings_manager import FindingsManager
from modules.api.phases.discovery import DiscoveryPhase
from modules.api.phases.authentication import AuthenticationPhase
from modules.api.phases.authorization import AuthorizationPhase
from modules.api.phases.fuzzing import FuzzingPhase


def _base_stubs(phase, phase_name: str, tmp_path) -> None:
    phase.PHASE_NAME = phase_name
    phase.output_dir = tmp_path
    phase.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None)
    phase.notes = SimpleNamespace(add=lambda *a, **k: None)
    phase.findings = FindingsManager()
    phase.loot = SimpleNamespace(add=lambda **k: None)
    phase.workflow = SimpleNamespace(add_step=lambda **k: None, record_result=lambda *a, **k: None,
                                      suggest_next=lambda **k: None, add_attack_path=lambda **k: None)
    phase.opsec = SimpleNamespace(check=lambda *a, **k: True)
    phase.tools_used = []


def _unavailable_tool():
    return SimpleNamespace(is_available=lambda: False)


def test_discovery_reports_failure_when_all_tools_unavailable(tmp_path):
    phase = DiscoveryPhase.__new__(DiscoveryPhase)
    _base_stubs(phase, "discovery", tmp_path)
    phase.httpx = _unavailable_tool()
    phase.ffuf = _unavailable_tool()
    phase.ffuf_parser = SimpleNamespace()
    phase.openapi_parser = SimpleNamespace()

    results = phase.run("https://api.target.local")

    assert results["success"] is False
    assert phase.tools_used == []


def test_discovery_reports_success_when_httpx_runs(tmp_path):
    phase = DiscoveryPhase.__new__(DiscoveryPhase)
    _base_stubs(phase, "discovery", tmp_path)
    phase.httpx = SimpleNamespace(
        is_available=lambda: True,
        probe=lambda url, headers=None: SimpleNamespace(success=True),
        probe_endpoints=lambda path, headers=None: SimpleNamespace(success=False),
        get_json_path=lambda kind: tmp_path / "httpx.json",
    )
    phase.ffuf = _unavailable_tool()
    phase.ffuf_parser = SimpleNamespace()
    phase.openapi_parser = SimpleNamespace()

    results = phase.run("https://api.target.local")

    assert results["success"] is True
    assert "httpx" in phase.tools_used


def test_authentication_reports_failure_when_nothing_available(tmp_path):
    phase = AuthenticationPhase.__new__(AuthenticationPhase)
    _base_stubs(phase, "authentication", tmp_path)
    phase.httpx = _unavailable_tool()
    phase.nuclei = _unavailable_tool()
    phase.nuclei_parser = SimpleNamespace()
    phase.openapi_parser = SimpleNamespace()

    results = phase.run("https://api.target.local")

    assert results["success"] is False
    assert phase.tools_used == []


def test_authentication_reports_success_from_spec_data_with_no_tool_call(tmp_path):
    """spec_data-only analysis needs no tool call at all — must still count as success."""
    phase = AuthenticationPhase.__new__(AuthenticationPhase)
    _base_stubs(phase, "authentication", tmp_path)
    phase.httpx = _unavailable_tool()
    phase.nuclei = _unavailable_tool()
    phase.nuclei_parser = SimpleNamespace()
    phase.openapi_parser = SimpleNamespace()

    from modules.api.parsers.openapi_parser import OpenApiSpec
    spec = OpenApiSpec(auth_schemes=[], endpoints=[])

    results = phase.run("https://api.target.local", spec_data=spec)

    assert results["success"] is True
    assert phase.tools_used == []


def test_authorization_reports_failure_when_nothing_available(tmp_path):
    phase = AuthorizationPhase.__new__(AuthorizationPhase)
    _base_stubs(phase, "authorization", tmp_path)
    phase.nuclei = _unavailable_tool()
    phase.httpx = _unavailable_tool()
    phase.nuclei_parser = SimpleNamespace()

    results = phase.run("https://api.target.local")

    assert results["success"] is False
    assert phase.tools_used == []


def test_authorization_reports_success_from_endpoints_with_no_tool_call(tmp_path):
    """Structural IDOR analysis on already-discovered endpoints needs no tool call."""
    phase = AuthorizationPhase.__new__(AuthorizationPhase)
    _base_stubs(phase, "authorization", tmp_path)
    phase.nuclei = _unavailable_tool()
    phase.httpx = _unavailable_tool()
    phase.nuclei_parser = SimpleNamespace()

    results = phase.run(
        "https://api.target.local",
        endpoints=[{"url": "https://api.target.local/users/123", "method": "DELETE", "status": 200}],
    )

    assert results["success"] is True
    assert phase.tools_used == []


def test_fuzzing_reports_failure_when_all_tools_unavailable(tmp_path):
    phase = FuzzingPhase.__new__(FuzzingPhase)
    _base_stubs(phase, "fuzzing", tmp_path)
    phase.arjun = _unavailable_tool()
    phase.ffuf = _unavailable_tool()
    phase.ffuf_parser = SimpleNamespace()
    phase.arjun_parser = SimpleNamespace()

    results = phase.run("https://api.target.local")

    assert results["success"] is False
    assert phase.tools_used == []


def test_fuzzing_reports_success_when_arjun_runs(tmp_path):
    phase = FuzzingPhase.__new__(FuzzingPhase)
    _base_stubs(phase, "fuzzing", tmp_path)
    phase.arjun = SimpleNamespace(
        is_available=lambda: True,
        discover_params=lambda url, method=None, headers=None: SimpleNamespace(success=False),
    )
    phase.ffuf = _unavailable_tool()
    phase.ffuf_parser = SimpleNamespace()
    phase.arjun_parser = SimpleNamespace()

    results = phase.run("https://api.target.local")

    assert results["success"] is True
    assert phase.tools_used == ["arjun"]
