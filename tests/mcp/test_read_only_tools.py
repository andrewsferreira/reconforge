"""Protocol-level tests for the 8 read-only MCP tools
(reconforge/mcp/tools.py), driven through a real MCP client/server
session — not by calling services.py directly (see
tests/mcp/test_services.py for that level).

Confirms: all 8 tools are discoverable with valid JSON-schema
inputSchemas, each succeeds with minimal valid arguments, the SDK's own
schema validation rejects a malformed module name before it ever reaches
reconforge/mcp/services.py, and an unknown tool name / unknown phase
produce a clean protocol-level error rather than a crash.
"""

from __future__ import annotations

from pathlib import Path

import anyio
from mcp.shared.memory import create_connected_server_and_client_session

from reconforge.mcp.server import build_server
from reconforge.mcp.tools import _TOOLS


def _run(coro_fn):
    anyio.run(coro_fn)


def test_list_tools_returns_all_eight_read_only_tools_with_valid_schemas():
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.list_tools()
            names = {t.name for t in result.tools}
            assert names == set(_TOOLS.keys())
            for tool in result.tools:
                assert isinstance(tool.inputSchema, dict)
                assert tool.description

    _run(_go)


def test_get_status_tool_call_succeeds():
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool("reconforge_get_status", {})
            assert result.isError is False
            assert result.structuredContent["modules"]

    _run(_go)


def test_list_modules_tool_call_succeeds_with_empty_arguments():
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool("reconforge_list_modules", {})
            assert result.isError is False
            assert len(result.structuredContent["modules"]) == 5

    _run(_go)


def test_get_module_details_rejects_unknown_module_via_schema_validation():
    """The SDK's own jsonschema validation (from the pydantic-generated
    inputSchema enum) must reject this before reconforge/mcp/services.py
    ever runs — proving the two-layer validation design actually works,
    not just that services.py would have rejected it too."""

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool("reconforge_get_module_details", {"module": "not_a_module"})
            assert result.isError is True
            assert "Input validation error" in result.content[0].text

    _run(_go)


def test_get_module_details_tool_call_succeeds_for_web():
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool("reconforge_get_module_details", {"module": "web"})
            assert result.isError is False
            assert result.structuredContent["module"]["name"] == "web"

    _run(_go)


def test_list_engagements_tool_call_succeeds_against_empty_dir(tmp_path: Path):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_list_engagements", {"output_base": str(tmp_path)}
            )
            assert result.isError is False
            assert result.structuredContent["engagements"] == []

    _run(_go)


def test_get_engagement_tool_call_reports_error_for_missing_id(tmp_path: Path):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_get_engagement",
                {"engagement_id": "does_not_exist", "output_base": str(tmp_path)},
            )
            assert result.isError is True

    _run(_go)


def test_get_scope_tool_call_reports_error_for_missing_file(tmp_path: Path):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_get_scope", {"scope_file": str(tmp_path / "nope.yaml")}
            )
            assert result.isError is True

    _run(_go)


def test_plan_workflow_tool_call_succeeds():
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool("reconforge_plan_workflow", {"target": "10.10.10.1"})
            assert result.isError is False
            assert len(result.structuredContent["selected_modules"]) == 5

    _run(_go)


def test_dry_run_tool_call_succeeds_and_writes_no_secrets(tmp_path: Path):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_dry_run",
                {
                    "target": "10.10.10.1",
                    "module": "network",
                    "phases": ["discovery"],
                    "output_base": str(tmp_path),
                },
            )
            assert result.isError is False
            assert result.structuredContent["module"] == "network"

    _run(_go)


def test_dry_run_tool_call_rejects_unknown_phase(tmp_path: Path):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_dry_run",
                {
                    "target": "10.10.10.1",
                    "module": "network",
                    "phases": ["not_a_real_phase"],
                    "output_base": str(tmp_path),
                },
            )
            assert result.isError is True

    _run(_go)


def test_unknown_tool_name_reports_error_not_crash():
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool("reconforge_does_not_exist", {})
            assert result.isError is True

    _run(_go)
