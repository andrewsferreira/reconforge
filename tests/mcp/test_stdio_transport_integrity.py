"""Regression test for a real bug found while manually verifying Phase 5:
core/logger.py::ReconLogger unconditionally logs to sys.stdout regardless
of verbose= (only the log level threshold changes, not whether stdout is
used at all). Any MCP tool that runs a real module — reconforge_dry_run,
reconforge_execute_approved_phase — therefore interleaved ANSI-colored
log lines into the stdio JSON-RPC stream and corrupted it, before
reconforge/mcp/server.py::run_stdio_async() started redirecting
sys.stdout to sys.stderr for the lifetime of the server run.

This class of bug is invisible to every other test in this package: the
in-memory transport (mcp.shared.memory.create_connected_server_and_client_session)
used everywhere else never touches actual process stdio, so it cannot
reproduce stdout corruption. Only a real subprocess, talking over its
actual stdin/stdout, can catch this — which is exactly what this file
does, and why it's slower and more limited in scope than the rest of
this package's test suite (2 tests, not exhaustive coverage).
"""

from __future__ import annotations

import logging
from pathlib import Path

import anyio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


class _ParseFailureCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.failures: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        message = record.getMessage()
        if "Failed to parse" in message:
            self.failures.append(message)


def _run_against_real_subprocess(tool_name: str, arguments: dict) -> tuple[bool, list[str]]:
    """Spawns the actual installed `reconforge mcp serve` console script,
    calls one tool over real stdio, and returns (isError, parse_failures).
    """
    capture = _ParseFailureCapture()
    logger = logging.getLogger("mcp.client.stdio")
    logger.addHandler(capture)
    try:

        async def _go() -> bool:
            params = StdioServerParameters(command="reconforge", args=["mcp", "serve"])
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(tool_name, arguments)
                    return bool(result.isError)

        is_error = anyio.run(_go)
        return is_error, capture.failures
    finally:
        logger.removeHandler(capture)


def test_dry_run_over_real_subprocess_does_not_corrupt_stdio(tmp_path: Path):
    is_error, failures = _run_against_real_subprocess(
        "reconforge_dry_run",
        {
            "target": "10.10.10.1",
            "module": "network",
            "phases": ["discovery"],
            "output_base": str(tmp_path),
        },
    )
    assert is_error is False
    assert failures == []


def test_execute_approved_phase_over_real_subprocess_does_not_corrupt_stdio(tmp_path: Path):
    is_error, failures = _run_against_real_subprocess(
        "reconforge_execute_approved_phase",
        {
            "engagement_id": "nope",
            "target": "10.10.10.1",
            "module": "surface",
            "phase": "vector_correlation",
            "output_base": str(tmp_path),
            "explicit_confirmation": True,
        },
    )
    assert is_error is False
    assert failures == []
