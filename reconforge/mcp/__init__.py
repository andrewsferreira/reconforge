"""ReconForge's MCP (Model Context Protocol) server package.

Lets Claude Desktop/Claude Code act as an MCP *client* against ReconForge
(the inverse relationship of ``core/adapters/burp/``, where ReconForge is
itself an MCP client of Burp's server). Stdio transport only — this
package never binds a network socket. See
docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md for the full design; the package
is being built incrementally, phase by phase, per that plan. As of this
version, all 12 read-only tools are registered (status, module/
engagement/scope listing, workflow planning, dry-run, findings/
reporting), plus three execution tools:
``reconforge_execute_approved_phase`` (blocks until the phase
finishes), and ``reconforge_start_execution``/
``reconforge_get_execution_status`` (returns a job id immediately,
poll for completion) — all three gated behind an active engagement, a
validated scope/approval, and explicit operator confirmation, and
sharing one process-wide execution lock. Credentialed phases (AD
delegation/bloodhound, network brute-forcing) are not executable
through MCP yet, and there is no execution cancellation (no
cooperative-cancellation hook exists in core/runner.py). It also
registers 7 read-only resources under the ``reconforge://`` URI scheme
(6 curated documentation pages plus a live module catalog) via
``reconforge/mcp/resources.py``, from a hardcoded allowlist rather than
any filesystem walk. No prompts are registered yet.
"""

from reconforge.mcp.server import build_server, run_stdio_server

__all__ = ["build_server", "run_stdio_server"]
