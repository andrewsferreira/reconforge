"""ReconForge's MCP server.

Phase 3 of docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md adds 8 read-only
inspection/planning tools (status, module listing, engagement/scope
inspection, workflow planning, dry-run) on top of the Phase 2 connection
foundation. No resources or prompts are registered yet, and no
execution/findings/reporting tools exist yet either — those are later
phases, registered against this same ``Server`` instance rather than a
duplicate one.

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
from reconforge.mcp import tools

SERVER_NAME = "reconforge"

SERVER_INSTRUCTIONS = (
    "ReconForge is a policy-gated reconnaissance framework for authorized "
    "penetration testing. This MCP server currently exposes read-only "
    "inspection/planning tools only (status, module/engagement/scope "
    "listing, workflow planning, dry-run) — no resources/prompts and no "
    "execution/findings/reporting tools yet. Any future execution "
    "capability will require an explicit engagement, a validated "
    "scope/approval, and explicit operator confirmation, and will never "
    "accept arbitrary shell or tool commands."
)


def build_server() -> Server:
    """Construct the ReconForge MCP server with its read-only tools registered.

    No resource/prompt handlers are registered on the returned server —
    ``Server.get_capabilities()`` reports those as unset, which is the
    accurate state for this phase.
    """
    server = Server(name=SERVER_NAME, version=RECONFORGE_VERSION, instructions=SERVER_INSTRUCTIONS)
    tools.register(server)
    return server


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
