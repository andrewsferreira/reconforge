"""Tests for reconforge/mcp/resources.py's list_resources/read_resource
handlers — MCP's second content-exposure primitive, distinct from
tools/, driven through a real MCP client/server session. Covers every
allowlisted URI, the unknown-URI error path, and audit-event parity
with tools.py's emit_tool_call_audit_event (see test_audit_events.py).
"""

from __future__ import annotations

import json

import anyio
import pytest
from mcp.shared.exceptions import McpError
from mcp.shared.memory import create_connected_server_and_client_session

from reconforge.mcp.resources import _ALL_URIS, _DOC_RESOURCES, _MODULES_URI
from reconforge.mcp.server import build_server


def _run(coro_fn):
    anyio.run(coro_fn)


def _last_json_line(stderr_text: str) -> dict:
    lines = [line for line in stderr_text.splitlines() if line.strip()]
    assert lines, "expected at least one stderr line"
    return json.loads(lines[-1])


def test_list_resources_includes_every_allowlisted_uri():
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.list_resources()
            uris = {str(r.uri) for r in result.resources}
            assert uris == _ALL_URIS
            assert len(uris) == 7

    _run(_go)


@pytest.mark.parametrize("uri", sorted(_DOC_RESOURCES))
def test_read_each_doc_resource_returns_nonempty_markdown(uri: str):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.read_resource(uri)
            assert len(result.contents) == 1
            content = result.contents[0]
            assert content.mimeType == "text/markdown"
            assert len(content.text) > 0

    _run(_go)


def test_read_modules_resource_returns_live_json_matching_the_tool():
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            resource_result = await session.read_resource(_MODULES_URI)
            assert resource_result.contents[0].mimeType == "application/json"
            resource_payload = json.loads(resource_result.contents[0].text)

            tool_result = await session.call_tool("reconforge_list_modules", {})
            assert resource_payload == tool_result.structuredContent

    _run(_go)


def test_read_unknown_resource_uri_raises_mcp_error():
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            with pytest.raises(McpError):
                await session.read_resource("reconforge://docs/not-a-real-doc")

    _run(_go)


# ── adversarial: path-traversal / off-allowlist URIs (MCP Phase 11) ──
#
# Two independent layers reject every case below: the mcp SDK's own
# pydantic AnyUrl parsing normalizes "../" segments out of the URI
# before resources.py ever sees it (confirmed by reading the resulting
# McpError's message, which always names the *normalized* string), and
# resources.py's allowlist membership check (`uri_str not in _ALL_URIS`)
# rejects anything that isn't one of the 7 exact, hardcoded URIs even if
# normalization somehow produced a real-looking one.


@pytest.mark.parametrize(
    "malicious_uri",
    [
        "reconforge://docs/../../../etc/passwd",
        "reconforge://docs/claude-mcp-integration/../../../../../../etc/passwd",
        "reconforge://modules/../../../../etc/passwd",
        "file:///etc/passwd",
        "reconforge://",
        "reconforge://docs/",
        "reconforge://docs/CLAUDE_MCP_IMPLEMENTATION_PLAN.md",
        "reconforge://docs/ARCHITECTURE_REVIEW.md",
    ],
)
def test_read_resource_rejects_every_path_traversal_and_off_allowlist_uri(malicious_uri: str):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            with pytest.raises(McpError):
                await session.read_resource(malicious_uri)

    _run(_go)


def test_list_resources_never_reveals_a_docs_directory_listing():
    """The allowlist is a fixed dict of 7 URIs, not a directory scan —
    this pins that invariant down directly against the doc filenames
    that exist on disk but were never added to the allowlist (e.g.
    ARCHITECTURE_REVIEW.md, CHANGELOG.md), so a future accidental
    filesystem-walk regression in resources.py would fail this test."""

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.list_resources()
            uris = {str(r.uri) for r in result.resources}
            assert "reconforge://docs/architecture-review" not in uris
            assert "reconforge://docs/changelog" not in uris
            assert len(uris) == 7

    _run(_go)


def test_successful_resource_read_emits_success_audit_event(
    capsys: pytest.CaptureFixture[str],
):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            await session.read_resource(_MODULES_URI)

    _run(_go)
    event = _last_json_line(capsys.readouterr().err)
    assert event["event"] == "mcp_resource_read"
    assert event["uri"] == _MODULES_URI
    assert event["outcome"] == "success"
    assert "error_code" not in event


def test_unknown_resource_read_emits_error_audit_event(
    capsys: pytest.CaptureFixture[str],
):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            with pytest.raises(McpError):
                await session.read_resource("reconforge://docs/not-a-real-doc")

    _run(_go)
    event = _last_json_line(capsys.readouterr().err)
    assert event["event"] == "mcp_resource_read"
    assert event["uri"] == "reconforge://docs/not-a-real-doc"
    assert event["outcome"] == "error"
    assert event["error_code"] == "MCP_SERVICE_ERROR"
