#!/usr/bin/env python3
"""Example: ask ReconForge's MCP server to plan a recon workflow.

Calls the read-only reconforge_plan_workflow tool against an example
target — this never executes anything, it only proposes which
modules/phases would run and their reconforge/mcp/policy.py execution
tier (SAFE_READ_ONLY..PROHIBITED). See docs/CLAUDE_MCP_INTEGRATION.md
for the full tool reference.

Usage:
    pip install -e ".[mcp]"
    python examples/claude_mcp/plan_workflow.py
"""

from __future__ import annotations

import asyncio
import json

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def main() -> None:
    params = StdioServerParameters(command="reconforge", args=["mcp", "serve"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        result = await session.call_tool(
            "reconforge_plan_workflow",
            {"target": "10.10.10.5", "modules": ["web"]},
        )
        print(json.dumps(result.structuredContent, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
