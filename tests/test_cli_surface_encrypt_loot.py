"""CLI tests for the surface module encryption parity."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _load_cli_module():
    """Load reconforge/cli.py as a standalone module (not via the package __init__)."""
    cli_path = Path(__file__).resolve().parents[1] / "reconforge" / "cli.py"
    spec = importlib.util.spec_from_file_location("reconforge_cli", cli_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_surface_parser_accepts_encrypt_loot():
    """Surface CLI should expose --encrypt-loot like other modules."""
    cli = _load_cli_module()
    parser = cli.build_parser()
    args = parser.parse_args(["surface", "--target", "10.10.10.1", "--encrypt-loot"])
    assert args.encrypt_loot is True


def test_surface_main_passes_encrypt_loot_to_module():
    """main() should forward args.encrypt_loot into SurfaceModule constructor."""
    cli = _load_cli_module()
    fake_module = MagicMock()
    fake_module.run.return_value = {"phases": {"port_discovery": {}}}

    with patch("modules.surface.surface_module.SurfaceModule", return_value=fake_module) as mock_surface:
        with patch.object(
            sys,
            "argv",
            ["reconforge", "surface", "--target", "10.10.10.1", "--encrypt-loot", "--dry-run"],
        ):
            with pytest.raises(SystemExit) as exc:
                cli.main()

    assert exc.value.code == 0
    assert mock_surface.call_args.kwargs["encrypt_loot"] is True
