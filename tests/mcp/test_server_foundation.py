"""Tests for the MCP server foundation (reconforge/mcp/server.py).

This is Phase 2 of docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md: the server has
zero tools/resources/prompts registered yet, so these tests pin down the
honest state of that foundation — a real stdio-protocol handshake works,
the server reports ReconForge's actual version, and calling any
capability that doesn't exist yet fails cleanly rather than silently
succeeding with fabricated data.

No ``pytest-asyncio`` dependency is added for this: async test bodies are
driven with ``anyio.run()`` directly, matching how ``mcp``'s own
in-memory test transport (``mcp.shared.memory``) is used elsewhere.
"""

import anyio
import pytest
from mcp.server.lowlevel import NotificationOptions
from mcp.shared.exceptions import McpError
from mcp.shared.memory import create_connected_server_and_client_session

from core.version import __version__ as RECONFORGE_VERSION
from reconforge.mcp.server import SERVER_NAME, build_server


def test_build_server_reports_reconforge_identity():
    server = build_server()
    assert server.name == SERVER_NAME == "reconforge"
    assert server.version == RECONFORGE_VERSION


def test_server_advertises_no_capabilities_yet():
    """No tool/resource/prompt handler is registered in this phase, so the
    server must not claim any of those capabilities during initialize."""
    server = build_server()
    capabilities = server.get_capabilities(NotificationOptions(), {})
    assert capabilities.tools is None
    assert capabilities.resources is None
    assert capabilities.prompts is None


def test_stdio_protocol_handshake_succeeds_over_real_mcp_session():
    """Drives a genuine MCP initialize handshake (client_info exchange,
    protocol negotiation, capability exchange) using the SDK's own
    in-memory client/server transport pair — not a hand-rolled mock."""

    async def _run() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as client_session:
            capabilities = client_session.get_server_capabilities()
            assert capabilities is not None
            assert capabilities.tools is None
            assert capabilities.resources is None

    anyio.run(_run)


def test_list_tools_fails_cleanly_because_none_are_registered_yet():
    """Calling a capability this phase doesn't implement must fail with a
    protocol-level error, not return a fabricated empty/success result."""

    async def _run() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as client_session:
            with pytest.raises(McpError):
                await client_session.list_tools()

    anyio.run(_run)


def test_list_resources_fails_cleanly_because_none_are_registered_yet():
    async def _run() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as client_session:
            with pytest.raises(McpError):
                await client_session.list_resources()

    anyio.run(_run)
