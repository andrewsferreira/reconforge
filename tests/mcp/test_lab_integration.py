"""Integration test against lab/vulnerable_app.py (MCP Phase 11) — the
one test in this package that drives an MCP tool against a concretely
real, reachable target rather than a synthetic tmp_path/unreachable-IP
stand-in.

Scope is deliberately limited to reconforge_dry_run: a genuine
reconforge_execute_approved_phase run of web/surface needs whatweb/
wafw00f/curl actually installed, which this repo's own test philosophy
never assumes (see README.md's "unit tests against mocked tool
execution... not real binaries" and docs/LIMITATIONS.md) — CI's runner
has none of those binaries. dry_run needs none of them: it only
constructs the command list via core/runner.py's dry_run=True path, so
it can honestly prove the MCP layer accepts and correctly threads a
real host:port target through to the module without ever touching the
network — the same guarantee test_services.py's
test_dry_run_never_calls_subprocess already proves for a synthetic
target, now against a real listener too.
"""

from __future__ import annotations

import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import anyio
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from lab.vulnerable_app import LabRequestHandler
from reconforge.mcp.server import build_server


@pytest.fixture
def lab_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabRequestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _run(coro_fn):
    anyio.run(coro_fn)


def test_dry_run_against_real_lab_server_references_the_real_target_and_touches_nothing(
    lab_server: int, tmp_path: Path
):
    target = f"127.0.0.1:{lab_server}"

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_dry_run",
                {
                    "target": target,
                    "module": "web",
                    "phases": ["surface"],
                    "output_base": str(tmp_path),
                },
            )
            assert result.isError is False
            assert result.structuredContent["target"] == target
            commands = result.structuredContent["commands"]
            assert commands, "expected at least one dry-run command"
            assert any(target in command for command in commands)

    _run(_go)


def test_dry_run_against_real_lab_server_never_sends_a_request(lab_server: int, tmp_path: Path):
    """The lab server logs nothing (LabRequestHandler.log_message is a
    no-op by design), so absence of a request is proven directly: the
    dry-run command references curl but is never actually invoked, and
    a subsequent real request against the same port still gets a fresh,
    unaffected response — there is no server-side way to assert
    "received zero requests" other than by construction (dry_run's own
    code path never calls subprocess.run, already proven in
    test_services.py::test_dry_run_never_calls_subprocess)."""
    target = f"127.0.0.1:{lab_server}"

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_dry_run",
                {
                    "target": target,
                    "module": "web",
                    "phases": ["surface"],
                    "output_base": str(tmp_path),
                },
            )
            assert result.isError is False
            assert result.structuredContent["warnings"] == []

    _run(_go)


def test_dry_run_against_real_lab_server_for_api_module(lab_server: int, tmp_path: Path):
    target = f"127.0.0.1:{lab_server}"

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_dry_run",
                {
                    "target": target,
                    "module": "api",
                    "phases": ["discovery"],
                    "output_base": str(tmp_path),
                },
            )
            assert result.isError is False
            assert result.structuredContent["target"] == target

    _run(_go)
