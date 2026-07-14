"""ReconForge's MCP server.

Phase 3 of docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md added 12 read-only
inspection/planning tools (status, module/engagement/scope listing,
workflow planning, dry-run, findings/reporting). Phase 5 added one
controlled-execution tool, ``reconforge_execute_approved_phase`` —
gated behind an active engagement, a validated scope/approval, and
explicit operator confirmation (see ``reconforge/mcp/policy.py``); it
never accepts arbitrary shell or tool commands, only a bounded
``(module, phase)`` pair already known to this codebase. Phase 6 added
two more execution tools (``reconforge_start_execution``/
``reconforge_get_execution_status``) sharing the same policy gate.
Phase 7 added a small set of read-only MCP *resources*
(``reconforge/mcp/resources.py``) — curated documentation plus a live
module catalog, addressed by a hardcoded ``reconforge://`` URI
allowlist, distinct from the tool-call interface above. No prompts are
registered yet — that would be a later phase, registered against this
same ``Server`` instance rather than a duplicate one.

Transport: stdio only. No network transport is implemented anywhere in
this package, so this server never binds a socket — a Claude Desktop or
Claude Code MCP client launches it as a subprocess and talks to it over
its stdin/stdout.
"""

from __future__ import annotations

import sys

import anyio
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from core.version import __version__ as RECONFORGE_VERSION
from reconforge.mcp import resources, tools

SERVER_NAME = "reconforge"

SERVER_INSTRUCTIONS = (
    "ReconForge is a policy-gated reconnaissance framework for authorized "
    "penetration testing. This MCP server exposes 12 read-only "
    "inspection/planning tools (status, module/engagement/scope listing, "
    "workflow planning, dry-run, findings/reporting) plus three execution "
    "tools — reconforge_execute_approved_phase (blocks until done), and "
    "reconforge_start_execution/reconforge_get_execution_status (returns a "
    "job id immediately, poll for the result) — all three requiring an "
    "active engagement, a validated scope/approval, and explicit operator "
    "confirmation for every call. None of them ever grants its own "
    "approval, and none accepts arbitrary shell or tool commands, only a "
    "bounded (module, phase) pair; all three share one process-wide "
    "execution lock, so only one runs at a time. Credentialed phases (AD "
    "delegation/bloodhound, network brute-forcing) are not executable "
    "through this server yet, and there is no execution cancellation. It "
    "also exposes 7 read-only resources under the reconforge:// URI "
    "scheme (6 curated documentation pages plus a live module catalog) — "
    "list them with resources/list. No prompts are registered yet."
)


def build_server() -> Server:
    """Construct the ReconForge MCP server with its tools and resources
    registered. No prompt handlers are registered on the returned
    server — ``Server.get_capabilities()`` reports that as unset, which
    is the accurate state for this phase.
    """
    server = Server(name=SERVER_NAME, version=RECONFORGE_VERSION, instructions=SERVER_INSTRUCTIONS)
    tools.register(server)
    resources.register(server)
    return server


async def run_stdio_async() -> None:
    """Run the MCP server over stdio until the client disconnects.

    stdio is the only transport implemented by this package. Nothing in
    this call path opens a network socket.
    """
    server = build_server()
    async with stdio_server() as (read_stream, write_stream):
        # stdio_server() already captured the real stdout's underlying
        # buffer for the JSON-RPC transport itself (it reads
        # sys.stdout.buffer once, synchronously, on entry — see
        # mcp.server.stdio.stdio_server's source), so reassigning
        # sys.stdout now is safe for the transport and necessary for
        # everything else: core/logger.py::ReconLogger unconditionally
        # logs to sys.stdout regardless of verbose= (only the log level
        # threshold changes, not whether stdout is used at all), so any
        # tool that runs a real module — reconforge_dry_run,
        # reconforge_execute_approved_phase — would otherwise interleave
        # ANSI-colored log lines into the JSON-RPC stream and corrupt it.
        # Confirmed with a real subprocess client (mcp.client.stdio),
        # which is the only way to catch this — the in-memory transport
        # used by this package's own tests never touches actual process
        # stdio, so it can't reproduce this class of bug.
        original_stdout = sys.stdout
        sys.stdout = sys.stderr
        try:
            await server.run(read_stream, write_stream, server.create_initialization_options())
        finally:
            sys.stdout = original_stdout


def run_stdio_server() -> None:
    """Synchronous entry point used by the ``reconforge mcp serve`` CLI command."""
    anyio.run(run_stdio_async)
