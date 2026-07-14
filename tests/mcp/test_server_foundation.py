"""Tests for the MCP server's identity and capability advertisement
(reconforge/mcp/server.py).

Phase 2 built the connection/handshake foundation with zero tools
registered; Phase 3 added 8 read-only tools (see
tests/mcp/test_read_only_tools.py for coverage of those tools
themselves); Phase 7 added read-only resources (see
tests/mcp/test_resources.py for coverage of the resources themselves).
This file now pins down the post-Phase-7 state: the ``tools`` and
``resources`` capabilities are both present, ``prompts`` is still
correctly absent (not implemented yet), and calling a capability that
genuinely doesn't exist (prompts) still fails cleanly rather than
fabricating an empty result.
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


def test_server_advertises_tools_and_resources_but_not_prompts():
    """15 tools (Phase 3/5/6) and 7 resources (Phase 7) are registered;
    prompts are not."""
    server = build_server()
    capabilities = server.get_capabilities(NotificationOptions(), {})
    assert capabilities.tools is not None
    assert capabilities.resources is not None
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
            assert capabilities.tools is not None
            assert capabilities.resources is not None

    anyio.run(_run)


def test_list_prompts_fails_cleanly_because_none_are_registered_yet():
    """Calling a capability this phase doesn't implement must fail with a
    protocol-level error, not return a fabricated empty/success result."""

    async def _run() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as client_session:
            with pytest.raises(McpError):
                await client_session.list_prompts()

    anyio.run(_run)
