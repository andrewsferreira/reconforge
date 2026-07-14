"""ReconForge's MCP (Model Context Protocol) server package.

Lets Claude Desktop/Claude Code act as an MCP *client* against ReconForge
(the inverse relationship of ``core/adapters/burp/``, where ReconForge is
itself an MCP client of Burp's server). Stdio transport only — this
package never binds a network socket. See
docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md for the full design; the package
is being built incrementally, phase by phase, per that plan. As of this
version, 8 read-only inspection/planning tools are registered (status,
module/engagement/scope listing, workflow planning, dry-run) — no
resources/prompts and no execution/findings/reporting tools yet.
"""

from reconforge.mcp.server import build_server, run_stdio_server

__all__ = ["build_server", "run_stdio_server"]
