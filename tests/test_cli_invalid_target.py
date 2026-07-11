"""CLI-level test that an invalid target fails cleanly (SystemExit, no raw traceback)."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


def _load_cli_module():
    cli_path = Path(__file__).resolve().parents[1] / "reconforge" / "cli.py"
    spec = importlib.util.spec_from_file_location("reconforge_cli", cli_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_main_exits_cleanly_on_invalid_target(capsys):
    cli = _load_cli_module()
    with patch.object(sys, "argv", ["reconforge", "network", "--target", "10.10.10.1; rm -rf /", "--dry-run"]):
        with pytest.raises(SystemExit) as exc:
            cli.main()

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "Invalid target" in captured.err
    assert "Traceback" not in captured.err
