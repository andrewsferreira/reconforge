#!/usr/bin/env python3
"""Example: query ReconForge's MCP server directly, outside of a Claude client.

Spawns `reconforge mcp serve` as a real subprocess and calls the
read-only reconforge_get_status tool over stdio -- the same protocol
Claude Desktop/Claude Code use. Useful for scripting, or just for
seeing the wire format. See docs/CLAUDE_MCP_INTEGRATION.md for the
full tool reference and the Claude Desktop/Code setup guide.

Usage:
    pip install -e ".[mcp]"
    python examples/claude_mcp/query_status.py
"""

from __future__ import annotations

import asyncio
import json

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def main() -> None:
    params = StdioServerParameters(command="reconforge", args=["mcp", "serve"])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("reconforge_get_status", {})
            print(json.dumps(result.structuredContent, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
