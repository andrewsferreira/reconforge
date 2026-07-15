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
this package's test suite.

Approving a request out-of-band, for real, requires the operator's
process and the MCP server's process to agree on where approval
requests live on disk. Here that's done by launching the real
subprocess with cwd=tmp_path (so its config-default
".reconforge/mcp_approvals" resolves under tmp_path) and pointing this
test's own approvals._approvals_dir() at that same resolved path — the
same separation of processes the real `reconforge mcp approvals
approve` CLI command relies on, just both sides pinned to a shared
tmp_path instead of the real cwd.
"""

from __future__ import annotations

import logging
from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from reconforge.mcp import approvals


class _ParseFailureCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.failures: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        message = record.getMessage()
        if "Failed to parse" in message:
            self.failures.append(message)


def _run_against_real_subprocess(
    tool_name: str, arguments: dict, *, cwd: str | None = None
) -> tuple[bool, list[str], dict]:
    """Spawns the actual installed `reconforge mcp serve` console script,
    calls one tool over real stdio, and returns (isError, parse_failures,
    structuredContent).
    """
    capture = _ParseFailureCapture()
    logger = logging.getLogger("mcp.client.stdio")
    logger.addHandler(capture)
    try:

        async def _go() -> tuple[bool, dict]:
            params = StdioServerParameters(command="reconforge", args=["mcp", "serve"], cwd=cwd)
            async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments)
                return bool(result.isError), (result.structuredContent or {})

        is_error, structured = anyio.run(_go)
        return is_error, capture.failures, structured
    finally:
        logger.removeHandler(capture)


def test_dry_run_over_real_subprocess_does_not_corrupt_stdio(tmp_path: Path):
    is_error, failures, _structured = _run_against_real_subprocess(
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
    """Exercises the error path (an unknown request_id) over real
    stdio — still enough to catch stdout corruption, without needing a
    genuinely approved request."""
    is_error, failures, _structured = _run_against_real_subprocess(
        "reconforge_execute_approved_phase",
        {"request_id": "not-a-real-request-id"},
    )
    assert is_error is True  # unknown request_id is correctly rejected
    assert failures == []


def test_start_execution_job_over_real_subprocess_does_not_corrupt_stdio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The job model (reconforge/mcp/jobs.py) runs the real module in a
    background thread rather than the request-handling coroutine —
    sys.stdout redirection is process-global, not thread-local, so this
    proves that still holds when the write happens from a different
    thread than the one server.py's run_stdio_async() set it up on, and
    that concurrent polling over the same stdio connection while the
    background thread is writing doesn't corrupt the JSON-RPC stream
    either. surface/vector_correlation is SAFE_READ_ONLY, so this needs
    no engagement/scope — only the out-of-band approval itself."""
    approvals_dir = tmp_path / ".reconforge" / "mcp_approvals"
    monkeypatch.setattr(approvals, "_approvals_dir", lambda: approvals_dir)

    capture = _ParseFailureCapture()
    logger = logging.getLogger("mcp.client.stdio")
    logger.addHandler(capture)
    try:

        async def _go() -> bool:
            params = StdioServerParameters(
                command="reconforge", args=["mcp", "serve"], cwd=str(tmp_path)
            )
            async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
                await session.initialize()
                created = await session.call_tool(
                    "reconforge_request_execution",
                    {
                        "engagement_id": "irrelevant-for-safe-read-only",
                        "target": "10.10.10.1",
                        "module": "surface",
                        "phase": "vector_correlation",
                        "output_base": str(tmp_path),
                    },
                )
                if created.isError:
                    return True
                request_id = created.structuredContent["request_id"]

                # Out-of-band approval: the same operation
                # `reconforge mcp approvals approve` performs, done
                # here as a direct call since both this test process
                # and the subprocess have been pointed at the same
                # tmp_path-rooted approvals directory.
                approvals.approve(request_id)

                start = await session.call_tool(
                    "reconforge_start_execution", {"request_id": request_id}
                )
                if start.isError:
                    return True
                job_id = start.structuredContent["job_id"]
                for _ in range(50):
                    status = await session.call_tool(
                        "reconforge_get_execution_status", {"job_id": job_id}
                    )
                    if status.isError:
                        return True
                    if status.structuredContent["status"] in ("completed", "failed"):
                        return status.structuredContent["status"] == "failed"
                    await anyio.sleep(0.05)
                return True  # never completed within the poll budget

        is_error = anyio.run(_go)
        assert is_error is False
        assert capture.failures == []
    finally:
        logger.removeHandler(capture)
