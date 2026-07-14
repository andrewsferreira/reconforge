"""Phase 21: APIModule._generate_reports() swallowed any exception during
the report-file writes with a bare `except Exception as e:
self.logger.error(...)` and no re-raise. Fixed to re-raise a typed
ModuleError instead — see modules/network/network_module.py's equivalent
test for the full rationale.
"""

import pytest
from types import SimpleNamespace

from core.exceptions import ModuleError
from core.findings_manager import FindingsManager
from core.output_manager import OutputManager
from modules.api.api_module import APIModule


def _make_module(tmp_path) -> APIModule:
    module = APIModule.__new__(APIModule)
    module.MODULE_NAME = "api"
    module.execution_id = "exec-1"
    module.target_str = "https://api.target.local"
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
    module.output = OutputManager(base_dir=str(tmp_path), target="https://api.target.local")
    module.module_dir = module.output.module_dir(module.MODULE_NAME)
    return module


def test_generate_reports_raises_module_error_instead_of_swallowing(tmp_path):
    module = _make_module(tmp_path)
    module.loot.save = lambda path: (_ for _ in ()).throw(OSError("disk full"))

    with pytest.raises(ModuleError) as exc_info:
        module._generate_reports({})

    assert exc_info.value.module == "api"
    assert "disk full" in str(exc_info.value)
