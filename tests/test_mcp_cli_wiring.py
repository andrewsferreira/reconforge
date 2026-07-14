"""Phase 2 (MCP Server Foundation): `reconforge mcp serve` CLI wiring.

Starting the MCP server is not itself an active scan against a target —
it has no `--target` — so it must not be blocked by the
`--authorized-target`/`--lab-mode`/`--enforce-scope` gate that guards
every other module. Any future execution reached *through* the server
(Phase 5+) enforces scope/approval independently at the point the scan
actually runs, via the same machinery covered by
tests/test_authorization_required_p5.py and tests/test_scope_gate_cli_p10.py.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


def _load_cli_module():
    cli_path = Path(__file__).resolve().parents[1] / "reconforge" / "cli.py"
    spec = importlib.util.spec_from_file_location("reconforge_cli", cli_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_build_parser_accepts_mcp_serve_subcommand():
    cli = _load_cli_module()
    parser = cli.build_parser()
    args = parser.parse_args(["mcp", "serve"])
    assert args.module == "mcp"
    assert args.mcp_command == "serve"


def test_main_dispatches_mcp_serve_without_any_authorization_flag():
    """No --authorized-target/--lab-mode/--enforce-scope/--dry-run needed."""
    cli = _load_cli_module()
    fake_run_stdio_server = MagicMock()

    with patch("reconforge.mcp.server.run_stdio_server", fake_run_stdio_server):
        with patch.object(sys, "argv", ["reconforge", "mcp", "serve"]):
            cli.main()

    fake_run_stdio_server.assert_called_once_with()


def test_main_errors_when_mcp_subcommand_is_missing(capsys):
    cli = _load_cli_module()
    with patch.object(sys, "argv", ["reconforge", "mcp"]):
        try:
            cli.main()
            raised = False
        except SystemExit as exc:
            raised = True
            assert exc.code == 2

    assert raised
    captured = capsys.readouterr()
    assert "mcp requires a supported subcommand" in captured.err
