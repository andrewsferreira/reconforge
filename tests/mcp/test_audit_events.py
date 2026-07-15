"""Tests for reconforge/mcp/audit.py and its wiring into
tools.py::_call_tool — every one of the 18 MCP tools passes through
that single choke point, so one JSON audit line to stderr is emitted
per call, success or failure, without needing per-tool instrumentation.
Also covers resources.py::_read_resource's analogous audit event.
"""

from __future__ import annotations

import json
from pathlib import Path

import anyio
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from reconforge.mcp import audit
from reconforge.mcp.audit import emit_resource_read_audit_event, emit_tool_call_audit_event
from reconforge.mcp.server import build_server


def _run(coro_fn):
    anyio.run(coro_fn)


def _last_json_line(stderr_text: str) -> dict:
    lines = [line for line in stderr_text.splitlines() if line.strip()]
    assert lines, "expected at least one stderr line"
    return json.loads(lines[-1])


def test_successful_tool_call_emits_success_audit_event(capsys: pytest.CaptureFixture[str]):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool("reconforge_get_status", {})
            assert result.isError is False

    _run(_go)
    event = _last_json_line(capsys.readouterr().err)
    assert event["event"] == "mcp_tool_call"
    assert event["tool"] == "reconforge_get_status"
    assert event["outcome"] == "success"
    assert "error_code" not in event
    assert "timestamp" in event
    assert event["session_id"] == audit.SESSION_ID


def test_tool_call_events_share_one_session_id_across_a_session(capsys: pytest.CaptureFixture[str]):
    """A Claude-directed sequence of tool calls (e.g. recommend_next_steps
    then request_execution) should be reconstructable from stderr as one
    session — see audit.SESSION_ID's docstring."""

    def _all_json_lines(stderr_text: str) -> list[dict]:
        return [json.loads(line) for line in stderr_text.splitlines() if line.strip()]

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            await session.call_tool("reconforge_get_status", {})
            await session.call_tool("reconforge_list_modules", {})

    _run(_go)
    events = _all_json_lines(capsys.readouterr().err)
    assert len(events) == 2
    session_ids = {e["session_id"] for e in events}
    assert session_ids == {audit.SESSION_ID}


def test_failed_tool_call_emits_error_audit_event_with_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_get_finding",
                {"finding_id": "does-not-exist", "output_base": str(tmp_path)},
            )
            assert result.isError is True

    _run(_go)
    event = _last_json_line(capsys.readouterr().err)
    assert event["outcome"] == "error"
    assert event["error_code"] == "FINDING_NOT_FOUND"
    assert event["tool"] == "reconforge_get_finding"


def test_unknown_tool_call_still_emits_audit_event(capsys: pytest.CaptureFixture[str]):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool("reconforge_not_a_real_tool", {})
            assert result.isError is True

    _run(_go)
    event = _last_json_line(capsys.readouterr().err)
    assert event["tool"] == "reconforge_not_a_real_tool"
    assert event["outcome"] == "error"
    assert event["error_code"] == "MCP_SERVICE_ERROR"


def test_approval_id_is_redacted_in_audit_event(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            await session.call_tool(
                "reconforge_request_execution",
                {
                    "engagement_id": "does_not_exist",
                    "target": "10.10.10.1",
                    "module": "web",
                    "phase": "surface",
                    "output_base": str(tmp_path),
                    "approval_id": "SUPER-SECRET-APPROVAL-TOKEN",
                },
            )

    _run(_go)
    stderr_text = capsys.readouterr().err
    event = _last_json_line(stderr_text)
    assert event["arguments"]["approval_id"] == "***REDACTED***"
    assert "SUPER-SECRET-APPROVAL-TOKEN" not in stderr_text


def test_emit_tool_call_audit_event_writes_single_valid_json_line(
    capsys: pytest.CaptureFixture[str],
):
    emit_tool_call_audit_event("some_tool", {"target": "10.10.10.1"}, outcome="success")
    out = capsys.readouterr()
    assert out.out == ""
    lines = [line for line in out.err.splitlines() if line.strip()]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["tool"] == "some_tool"
    assert parsed["arguments"] == {"target": "10.10.10.1"}


def test_emit_resource_read_audit_event_writes_single_valid_json_line(
    capsys: pytest.CaptureFixture[str],
):
    emit_resource_read_audit_event("reconforge://modules", outcome="success")
    out = capsys.readouterr()
    assert out.out == ""
    lines = [line for line in out.err.splitlines() if line.strip()]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["event"] == "mcp_resource_read"
    assert parsed["uri"] == "reconforge://modules"
    assert parsed["outcome"] == "success"
    assert "error_code" not in parsed


def test_emit_resource_read_audit_event_includes_error_code_on_failure(
    capsys: pytest.CaptureFixture[str],
):
    emit_resource_read_audit_event(
        "reconforge://docs/not-a-real-doc", outcome="error", error_code="MCP_SERVICE_ERROR"
    )
    parsed = json.loads(capsys.readouterr().err.strip())
    assert parsed["outcome"] == "error"
    assert parsed["error_code"] == "MCP_SERVICE_ERROR"
