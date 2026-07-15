"""Phase 21: NetworkModule._generate_reports() swallowed any exception
during the 9-10 independent report-file writes with a bare
`except Exception as e: self.logger.error(...)` and no re-raise — a
failure partway through (e.g. a disk-full error on one write) silently
left later artifacts (including, ironically, the evidence manifest
itself) un-written while run() still returned a normal-looking success.
Fixed to re-raise a typed ModuleError instead of swallowing.
"""

from types import SimpleNamespace

import pytest

from core.exceptions import ModuleError
from core.findings_manager import FindingsManager
from core.output_manager import OutputManager
from modules.network.network_module import NetworkModule


def _make_module(tmp_path) -> NetworkModule:
    module = NetworkModule.__new__(NetworkModule)
    module.MODULE_NAME = "network"
    module.execution_id = "exec-1"
    module.target_str = "10.10.10.1"
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
    return module


def test_generate_reports_raises_module_error_instead_of_swallowing(tmp_path):
    module = _make_module(tmp_path)

    def failing_save(path):
        raise OSError("disk full")

    module.loot.save = failing_save

    with pytest.raises(ModuleError) as exc_info:
        module._generate_reports({})

    assert exc_info.value.module == "network"
    assert "disk full" in str(exc_info.value)


def test_generate_reports_original_exception_is_chained(tmp_path):
    module = _make_module(tmp_path)
    original = OSError("disk full")
    module.loot.save = lambda path: (_ for _ in ()).throw(original)

    with pytest.raises(ModuleError) as exc_info:
        module._generate_reports({})

    assert exc_info.value.__cause__ is original
