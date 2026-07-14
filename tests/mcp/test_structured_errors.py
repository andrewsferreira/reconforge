"""Protocol-level tests for reconforge/mcp/tools.py::_error_result — the
structured error path added so a client can act on ``error_code`` (and,
for policy denials, ``missing_requirements``) instead of parsing the
free-text message. Before this, every ``MCPServiceError`` fell through to
the `mcp` SDK's own generic ``except Exception as e: return
self._make_error_result(str(e))``, which only ever produces plain text —
each subclass's ``code`` class attribute was declared but never actually
reached the client.
"""

from __future__ import annotations

from pathlib import Path

import anyio
from mcp.shared.memory import create_connected_server_and_client_session

from reconforge.mcp import services
from reconforge.mcp.server import build_server


def _run(coro_fn):
    anyio.run(coro_fn)


def test_unknown_tool_name_returns_structured_generic_code():
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool("reconforge_not_a_real_tool", {})
            assert result.isError is True
            assert result.structuredContent is not None
            assert result.structuredContent["error_code"] == "MCP_SERVICE_ERROR"
            assert "Unknown tool" in result.structuredContent["message"]
            assert "missing_requirements" not in result.structuredContent

    _run(_go)


def test_finding_not_found_returns_structured_code(tmp_path: Path):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_get_finding",
                {"finding_id": "does-not-exist", "output_base": str(tmp_path)},
            )
            assert result.isError is True
            assert result.structuredContent["error_code"] == "FINDING_NOT_FOUND"
            assert "missing_requirements" not in result.structuredContent

    _run(_go)


def test_unknown_phase_returns_structured_code(tmp_path: Path):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_execute_approved_phase",
                {
                    "engagement_id": "does_not_exist",
                    "target": "10.10.10.1",
                    "module": "web",
                    "phase": "not_a_real_phase",
                    "output_base": str(tmp_path),
                },
            )
            assert result.isError is True
            assert result.structuredContent["error_code"] == "UNKNOWN_PHASE"

    _run(_go)


def test_policy_blocked_without_any_approval_surfaces_missing_requirements(tmp_path: Path):
    """web/exploit is INTRUSIVE-tier — the only tier below CREDENTIAL_USE
    that also requires approval_id, so this exercises all four
    requirement kinds at once (engagement, scope, confirmation, approval)."""

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_execute_approved_phase",
                {
                    "engagement_id": "does_not_exist",
                    "target": "10.10.10.1",
                    "module": "web",
                    "phase": "exploit",
                    "output_base": str(tmp_path),
                },
            )
            assert result.isError is True
            assert result.structuredContent["error_code"] == "POLICY_BLOCKED"
            missing = result.structuredContent["missing_requirements"]
            assert "engagement_id" in missing
            assert "explicit_confirmation=true" in missing
            assert "approval_id" in missing

    _run(_go)


def test_credential_use_rejection_has_no_missing_requirements(tmp_path: Path):
    """CREDENTIAL_USE is rejected outright before the requirements check
    even runs — there's nothing "missing" the operator could supply to fix
    it, so the key shouldn't appear (as opposed to being present-but-empty)."""

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_execute_approved_phase",
                {
                    "engagement_id": "does_not_exist",
                    "target": "10.10.10.1",
                    "module": "ad",
                    "phase": "bloodhound",
                    "domain": "corp.local",
                    "output_base": str(tmp_path),
                    "explicit_confirmation": True,
                },
            )
            assert result.isError is True
            assert result.structuredContent["error_code"] == "POLICY_BLOCKED"
            assert "missing_requirements" not in result.structuredContent

    _run(_go)


def test_execution_conflict_returns_structured_code(tmp_path: Path):
    async def _go() -> None:
        server = build_server()
        assert services._EXECUTION_LOCK.acquire(blocking=False)
        try:
            async with create_connected_server_and_client_session(server) as session:
                result = await session.call_tool(
                    "reconforge_execute_approved_phase",
                    {
                        "engagement_id": "does_not_exist",
                        "target": "10.10.10.1",
                        "module": "surface",
                        "phase": "vector_correlation",
                        "output_base": str(tmp_path),
                        "explicit_confirmation": True,
                    },
                )
                assert result.isError is True
                assert result.structuredContent["error_code"] == "EXECUTION_CONFLICT"
        finally:
            services._EXECUTION_LOCK.release()

    _run(_go)
