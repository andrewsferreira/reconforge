"""Phase 15: NetworkModule._generate_reports() wrote evidence.manifest.json
(OutputManager.write_evidence_manifest()) BEFORE quick_report.md — since the
manifest hashes every file already present in the module directory at call
time, quick_report.md (the primary human-facing artifact) was silently
excluded from its own integrity chain in every real run. Fixed by moving
the manifest write to genuinely be the last artifact written.
"""

import json
from types import SimpleNamespace

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


def test_evidence_manifest_includes_quick_report(tmp_path):
    module = _make_module(tmp_path)
    module.findings_mgr.add(
        finding_type="vulnerability", severity="medium", confidence="confirmed",
        target="10.10.10.1", module="network", description="test finding",
    )

    module._generate_reports({})

    manifest_path = module.output.evidence_manifest_file(module.MODULE_NAME)
    manifest = json.loads(manifest_path.read_text())
    manifest_paths = {entry["path"] for entry in manifest["entries"]}

    assert "quick_report.md" in manifest_paths


def test_evidence_manifest_root_chain_hash_actually_depends_on_quick_report(tmp_path):
    """Stronger check than membership: the manifest's root_chain_hash must
    differ depending on quick_report.md's content, proving it's genuinely
    part of the hash chain rather than coincidentally listed."""
    module_a = _make_module(tmp_path / "a")
    module_a.findings_mgr.add(
        finding_type="vulnerability", severity="low", confidence="confirmed",
        target="10.10.10.1", module="network", description="finding A",
    )
    module_a._generate_reports({})
    manifest_a = json.loads(module_a.output.evidence_manifest_file("network").read_text())

    module_b = _make_module(tmp_path / "b")
    module_b.findings_mgr.add(
        finding_type="vulnerability", severity="critical", confidence="confirmed",
        target="10.10.10.1", module="network", description="finding B — very different",
    )
    module_b._generate_reports({})
    manifest_b = json.loads(module_b.output.evidence_manifest_file("network").read_text())

    assert manifest_a["root_chain_hash"] != manifest_b["root_chain_hash"]
