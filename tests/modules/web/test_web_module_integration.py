"""Integration-style smoke tests for WebModule phase orchestration."""

from unittest.mock import MagicMock

from modules.web.web_module import WebModule


def _stub_web_module(module: WebModule) -> None:
    """Patch heavy side-effects/tools for orchestration-focused tests."""
    module._check_tools = MagicMock(return_value={})
    module._generate_reports = MagicMock()
    module._print_summary = MagicMock()

    module.phase_surface.execute = MagicMock(return_value={"waf": {"detected": True}, "technologies": ["wordpress"]})
    module.phase_content.execute = MagicMock(return_value={"paths": ["/admin"]})
    module.phase_vuln.execute = MagicMock(return_value={"nuclei_findings": []})
    module.phase_exploit.execute = MagicMock(return_value={"candidates": []})


def test_web_module_default_run_executes_surface_content_vuln_only(tmp_path):
    module = WebModule(target="http://example.local", output_base=str(tmp_path), dry_run=True)
    _stub_web_module(module)

    result = module.run()

    assert result["success"] is True
    assert set(result["phases"].keys()) == {"surface", "content", "vuln"}
    assert module.phase_surface.execute.called
    assert module.phase_content.execute.called
    assert module.phase_vuln.execute.called
    assert not module.phase_exploit.execute.called

    # Content phase consumes WAF signal from surface phase
    assert module.phase_content.execute.call_args.kwargs["waf_detected"] is True


def test_web_module_exploit_phase_forces_opt_in_when_requested(tmp_path):
    module = WebModule(target="example.local", output_base=str(tmp_path), dry_run=True)
    _stub_web_module(module)

    result = module.run(phases=["exploit"], opt_in=False)

    assert result["success"] is True
    assert set(result["phases"].keys()) == {"exploit"}
    assert module.phase_exploit.execute.call_args.kwargs["opt_in"] is True
