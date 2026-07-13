"""Phase 11-D: SurfaceDiscoveryPhase._run_wafw00f() was the only
tool-invoking method in this file that didn't check run_result.success
before trusting parsed output (contrast _run_whatweb(), two methods above
it, which does). A wafw00f execution failure (missing binary, network
error, timeout) was indistinguishable from a genuine "no WAF detected"
finding.
"""

from types import SimpleNamespace

from core.findings_manager import FindingsManager
from modules.web.phases.surface_discovery import SurfaceDiscoveryPhase


def _make_phase(run_success: bool) -> SurfaceDiscoveryPhase:
    phase = SurfaceDiscoveryPhase.__new__(SurfaceDiscoveryPhase)
    phase.PHASE_NAME = "surface_discovery"
    phase.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None)
    phase.notes = SimpleNamespace(
        add=lambda *a, **k: None,
        add_command_note=lambda *a, **k: None,
        add_finding_note=lambda *a, **k: None,
    )
    phase.findings = FindingsManager()
    phase.loot = SimpleNamespace(add_service=lambda **k: None)
    phase.workflow = SimpleNamespace(
        add_step=lambda **k: None,
        record_result=lambda *a, **k: None,
        add_rabbit_hole=lambda *a, **k: None,
        suggest_next=lambda **k: None,
    )
    phase.tools_used = []
    phase.opsec = SimpleNamespace(check=lambda *a, **k: True)
    phase.wafw00f = SimpleNamespace(
        is_available=lambda: True,
        detect=lambda url: SimpleNamespace(
            success=run_success, stdout="", stderr="wafw00f: command not found",
            command="wafw00f https://target.local",
        ),
        get_output_path=lambda: "wafw00f_output.txt",
    )
    phase.wafw00f_parser = SimpleNamespace(
        parse_file=lambda path: SimpleNamespace(waf_detected=False, waf_names=[], raw_output=""),
        parse_text=lambda text: SimpleNamespace(waf_detected=False, waf_names=[], raw_output=""),
    )
    return phase


def test_wafw00f_failure_produces_no_finding():
    phase = _make_phase(run_success=False)
    results = {}

    count = phase._run_wafw00f("https://target.local", results)

    assert count == 0
    assert phase.findings.get_all() == []
    assert "waf" not in results


def test_wafw00f_success_with_no_waf_still_reports_finding():
    phase = _make_phase(run_success=True)
    results = {}

    count = phase._run_wafw00f("https://target.local", results)

    assert count == 1
    findings = phase.findings.get_all()
    assert findings[0].description == "No WAF detected"
    assert results["waf"] == {"detected": False, "products": []}
