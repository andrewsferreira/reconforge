import importlib.util
from pathlib import Path

import pytest


def _load_cli_module():
    cli_path = Path(__file__).resolve().parents[1] / "reconforge.py"
    spec = importlib.util.spec_from_file_location("reconforge_cli", cli_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_enforce_scope_gate_noop_when_disabled():
    cli = _load_cli_module()
    parser = cli.build_parser()
    args = parser.parse_args(["surface", "--target", "10.10.10.1"])
    cli.enforce_scope_gate(args)


def test_enforce_scope_gate_requires_scope_file_and_approval_id():
    cli = _load_cli_module()
    parser = cli.build_parser()
    args = parser.parse_args(["surface", "--target", "10.10.10.1", "--enforce-scope"])
    with pytest.raises(ValueError, match="scope-file"):
        cli.enforce_scope_gate(args)
