"""Structural guardrail (MCP Phase 11): no MCP-layer module ever imports
core.credential_vault.CredentialVault or core.loot_manager.LootManager.

This is a distinct threat from tests/mcp/test_findings_and_reports.py's
secret-redaction coverage (a fake secret embedded in *scanned-target
evidence text*, sanitized via sanitize_log()) — this test is about
ReconForge's own operator-supplied/discovered credential store, which
none of the 15 MCP tools' response schemas expose a field for and none
of reconforge/mcp/services.py's functions ever read from. A real module
instantiated by dry_run/execute_approved_phase (e.g. WebModule) does
use LootManager/CredentialVault internally exactly as the CLI already
does, contributing discovered credentials to disk — that pre-existing
CLI behavior is untouched and out of scope here. What this test pins
down is narrower and MCP-specific: nothing in the request/response
service layer itself can read the vault back out through a tool call.
Import-time is checked (not a runtime call-graph trace) because it is
a hard, cheap invariant — no MCP service function needs to import
either class, and if one starts importing it, that is a deliberate
enough change to warrant updating this test explicitly rather than
slipping in silently.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_MCP_PACKAGE_DIR = Path(__file__).resolve().parents[2] / "reconforge" / "mcp"
_FORBIDDEN_IMPORTS = frozenset({"CredentialVault", "LootManager"})


def _imported_names(source_path: Path) -> set[str]:
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.name.rsplit(".", 1)[-1] for alias in node.names)
    return names


@pytest.mark.parametrize(
    "module_file",
    sorted(p for p in _MCP_PACKAGE_DIR.glob("*.py") if p.name != "__init__.py"),
    ids=lambda p: p.name,
)
def test_mcp_module_never_imports_credential_vault_or_loot_manager(module_file: Path):
    imported = _imported_names(module_file)
    leaked = imported & _FORBIDDEN_IMPORTS
    assert not leaked, f"{module_file.name} imports {leaked} — a credential-store exposure risk for an MCP tool"
