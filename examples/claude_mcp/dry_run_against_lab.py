#!/usr/bin/env python3
"""Example: a genuinely safe, self-contained MCP demonstration.

Starts lab/vulnerable_app.py (the first-party, stdlib-only local
validation target — see README.md's "Local Validation Lab" section) on
loopback, then calls the real reconforge_dry_run tool against it
through a real MCP client/server session. No external network access,
no third-party tooling, and no real request ever reaches the lab
server: dry_run only constructs the command ReconForge *would* run
(core/runner.py's dry_run=True path never calls subprocess.run). This
is the safest possible way to see end-to-end MCP behavior against a
concretely real, reachable target rather than a synthetic IP that was
never actually going to be scanned. See docs/CLAUDE_MCP_INTEGRATION.md
for the full tool reference and Claude Desktop/Code setup guide.

Usage:
    pip install -e ".[mcp]"
    python examples/claude_mcp/dry_run_against_lab.py
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import ThreadingHTTPServer

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from lab.vulnerable_app import LabRequestHandler


async def main() -> None:
    lab_server = ThreadingHTTPServer(("127.0.0.1", 0), LabRequestHandler)
    lab_port = lab_server.server_address[1]
    lab_thread = threading.Thread(target=lab_server.serve_forever, daemon=True)
    lab_thread.start()
    print(f"Lab target listening on 127.0.0.1:{lab_port} (loopback only)\n")

    try:
        params = StdioServerParameters(command="reconforge", args=["mcp", "serve"])
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "reconforge_dry_run",
                {
                    "target": f"127.0.0.1:{lab_port}",
                    "module": "web",
                    "phases": ["surface"],
                    "output_base": "outputs",
                },
            )
            print(json.dumps(result.structuredContent, indent=2))
    finally:
        lab_server.shutdown()
        lab_server.server_close()
        lab_thread.join(timeout=2)


if __name__ == "__main__":
    asyncio.run(main())
