"""Phase 5-D: no active execution without an explicit authorization signal."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _load_cli_module():
    cli_path = Path(__file__).resolve().parents[1] / "reconforge" / "cli.py"
    spec = importlib.util.spec_from_file_location("reconforge_cli", cli_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_require_authorization_raises_without_any_signal():
    cli = _load_cli_module()
    parser = cli.build_parser()
    args = parser.parse_args(["surface", "--target", "10.10.10.1"])
    with pytest.raises(ValueError, match="Authorization required"):
        cli.require_authorization(args, scope=None)


def test_require_authorization_noop_on_dry_run():
    cli = _load_cli_module()
    parser = cli.build_parser()
    args = parser.parse_args(["surface", "--target", "10.10.10.1", "--dry-run"])
    cli.require_authorization(args, scope=None)


def test_require_authorization_noop_with_authorized_target_flag():
    cli = _load_cli_module()
    parser = cli.build_parser()
    args = parser.parse_args(["surface", "--target", "10.10.10.1", "--authorized-target"])
    cli.require_authorization(args, scope=None)


def test_require_authorization_noop_with_lab_mode_flag():
    cli = _load_cli_module()
    parser = cli.build_parser()
    args = parser.parse_args(["surface", "--target", "10.10.10.1", "--lab-mode"])
    cli.require_authorization(args, scope=None)


def test_require_authorization_noop_with_validated_scope():
    cli = _load_cli_module()
    parser = cli.build_parser()
    args = parser.parse_args(["surface", "--target", "10.10.10.1"])
    cli.require_authorization(args, scope=object())


def test_main_exits_with_error_when_no_authorization_signal(capsys):
    """End-to-end: main() refuses to dispatch without --dry-run/--authorized-target/--lab-mode/--enforce-scope."""
    cli = _load_cli_module()
    with patch.object(
        sys,
        "argv",
        ["reconforge", "surface", "--target", "10.10.10.1"],
    ):
        with pytest.raises(SystemExit) as exc:
            cli.main()

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "Authorization required" in captured.err


def test_main_dispatches_with_lab_mode_flag():
    """--lab-mode alone is sufficient to satisfy the authorization gate."""
    cli = _load_cli_module()
    fake_module = MagicMock()
    fake_module.run.return_value = {"phases": {"port_discovery": {}}}

    with patch("modules.surface.surface_module.SurfaceModule", return_value=fake_module):
        with patch.object(
            sys,
            "argv",
            ["reconforge", "surface", "--target", "10.10.10.1", "--lab-mode"],
        ):
            with pytest.raises(SystemExit) as exc:
                cli.main()

    assert exc.value.code == 0
