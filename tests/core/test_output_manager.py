from core.output_manager import OutputManager


def test_write_evidence_manifest_creates_chain(tmp_path):
    om = OutputManager(base_dir=str(tmp_path), target="10.10.10.1")
    module = "network"
    mod_dir = om.module_dir(module)
    (mod_dir / "findings.json").write_text('{"ok": true}', encoding="utf-8")
    (mod_dir / "commands.log").write_text("nmap -sV\n", encoding="utf-8")

    manifest_path = om.write_evidence_manifest(module, execution_id="run_123")
    payload = manifest_path.read_text(encoding="utf-8")

    assert manifest_path.name == "evidence.manifest.json"
    assert '"execution_id": "run_123"' in payload
    assert '"root_chain_hash"' in payload
    assert '"findings.json"' in payload
    assert '"commands.log"' in payload
