"""Phase 21: ADModule._generate_reports() swallowed any exception during
the report-file writes with a bare `except Exception as e:
self.logger.error(...)` and no re-raise. Fixed to re-raise a typed
ModuleError instead — see modules/network/network_module.py's equivalent
test for the full rationale.
"""

from types import SimpleNamespace

import pytest

from core.exceptions import ModuleError
from core.findings_manager import FindingsManager
from core.output_manager import OutputManager
from modules.ad.ad_module import ADModule


def _stub_reporter():
    return SimpleNamespace(
        generate=lambda *a, **k: "content",
        save=lambda content, path: path.write_text(content),
    )


def _make_module(tmp_path) -> ADModule:
    module = ADModule.__new__(ADModule)
    module.MODULE_NAME = "ad"
    module.execution_id = "exec-1"
    module.target_str = "10.10.10.1"
    module.domain = "corp.local"
    module.dc_ip = "10.10.10.1"
    module.username = ""
    module.opsec_mode = "normal"
    module.logger = SimpleNamespace(info=lambda *a, **k: None, error=lambda *a, **k: None)
    module.findings_mgr = FindingsManager()
    module.notes = SimpleNamespace(save=lambda path: path.write_text("notes"))
    module.workflow = SimpleNamespace(
        to_markdown=lambda: "# Attack Workflow",
        attack_paths=[], get_suggestions=lambda: [],
    )
    module.runner = SimpleNamespace(save_command_log=lambda path: path.write_text("[]"))
    module.loot = SimpleNamespace(
        save=lambda path: path.write_text("[]"),
        save_contract=lambda path, **k: path.write_text("{}"),
        summary=lambda: {},
    )
    module.output = OutputManager(base_dir=str(tmp_path), target="10.10.10.1")
    module.module_dir = module.output.module_dir(module.MODULE_NAME)
    module.attack_surface_reporter = _stub_reporter()
    module.hvt_reporter = _stub_reporter()
    module.attack_path_reporter = _stub_reporter()
    module.remediation_reporter = _stub_reporter()
    module.ad_summary_reporter = _stub_reporter()
    return module


def test_generate_reports_raises_module_error_instead_of_swallowing(tmp_path):
    module = _make_module(tmp_path)
    module.loot.save = lambda path: (_ for _ in ()).throw(OSError("disk full"))

    with pytest.raises(ModuleError) as exc_info:
        module._generate_reports({})

    assert exc_info.value.module == "ad"
    assert "disk full" in str(exc_info.value)


def test_generate_reports_succeeds_when_nothing_fails(tmp_path):
    """Sanity check that the harness itself is correctly wired — a
    successful run must not raise."""
    module = _make_module(tmp_path)
    module._generate_reports({})
