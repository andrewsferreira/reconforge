"""Foundation for ReconForge's MCP server.

Phase 2 of docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md: this module builds and
runs a stdio-only MCP server with zero tools, resources, or prompts
registered. Read-only inspection tools (status, module listing, dry-run,
findings, reports, ...) are added in a later phase against this same
``Server`` instance — this module is the connection/handshake foundation
only, not a stub pretending to be more.

Transport: stdio only. No network transport is implemented anywhere in
this package, so this server never binds a socket — a Claude Desktop or
Claude Code MCP client launches it as a subprocess and talks to it over
its stdin/stdout.
"""

from __future__ import annotations

import anyio
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from core.version import __version__ as RECONFORGE_VERSION

SERVER_NAME = "reconforge"

SERVER_INSTRUCTIONS = (
    "ReconForge is a policy-gated reconnaissance framework for authorized "
    "penetration testing. This MCP server currently exposes no tools, "
    "resources, or prompts (connection foundation phase). Read-only "
    "inspection capabilities are added in a later phase; any future "
    "execution capability will require an explicit engagement, a "
    "validated scope/approval, and explicit operator confirmation, and "
    "will never accept arbitrary shell or tool commands."
)


def build_server() -> Server:
    """Construct the ReconForge MCP server.

    No tool/resource/prompt handlers are registered on the returned
    server. ``Server.get_capabilities()`` therefore reports ``tools``,
    ``resources``, and ``prompts`` as unset, which is the accurate state
    for this phase — later phases register handlers on this same
    construction point rather than duplicating server setup.
    """
    return Server(name=SERVER_NAME, version=RECONFORGE_VERSION, instructions=SERVER_INSTRUCTIONS)


async def run_stdio_async() -> None:
    """Run the MCP server over stdio until the client disconnects.

    stdio is the only transport implemented by this package. Nothing in
    this call path opens a network socket.
    """
    server = build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def run_stdio_server() -> None:
    """Synchronous entry point used by the ``reconforge mcp serve`` CLI command."""
    anyio.run(run_stdio_async)
