"""Protocol-level tests for the 4 findings/reporting MCP tools
(reconforge_get_findings, reconforge_get_finding,
reconforge_summarize_findings, reconforge_generate_report), driven
through a real MCP client/server session — see
tests/mcp/test_findings_and_reports.py for direct services.py coverage,
including the security-critical prompt-injection/secret-redaction test.
"""

from __future__ import annotations

import json
from pathlib import Path

import anyio
from mcp.shared.memory import create_connected_server_and_client_session

from reconforge.mcp.server import build_server
from reconforge.mcp.tools import _TOOLS


def _run(coro_fn):
    anyio.run(coro_fn)


def _write_finding(tmp_path: Path, target: str, module: str, finding_id: str) -> None:
    module_dir = tmp_path / target / module
    module_dir.mkdir(parents=True, exist_ok=True)
    (module_dir / "findings.json").write_text(
        json.dumps(
            [
                {
                    "id": finding_id,
                    "finding_type": "vulnerability",
                    "severity": "high",
                    "confidence": "confirmed",
                    "confidence_reason": "test",
                    "target": target,
                    "module": module,
                    "phase": "scanning",
                    "description": "test finding",
                    "evidence": "",
                    "recommendation": "fix it",
                    "references": [],
                    "timestamp": "2026-07-14T00:00:00",
                }
            ]
        )
    )


def test_list_tools_now_includes_all_twelve_read_only_tools():
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.list_tools()
            names = {t.name for t in result.tools}
            assert names == set(_TOOLS.keys())
            assert len(names) == 12

    _run(_go)


def test_get_findings_tool_call_succeeds(tmp_path: Path):
    _write_finding(tmp_path, "10.10.10.1", "network", "f1")

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_get_findings", {"output_base": str(tmp_path)}
            )
            assert result.isError is False
            assert result.structuredContent["total_count"] == 1

    _run(_go)


def test_get_finding_tool_call_reports_error_for_missing_id(tmp_path: Path):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_get_finding",
                {"finding_id": "nope", "output_base": str(tmp_path)},
            )
            assert result.isError is True

    _run(_go)


def test_summarize_findings_tool_call_succeeds(tmp_path: Path):
    _write_finding(tmp_path, "10.10.10.1", "network", "f1")

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_summarize_findings", {"output_base": str(tmp_path)}
            )
            assert result.isError is False
            assert result.structuredContent["total"] == 1

    _run(_go)


def test_generate_report_tool_call_succeeds(tmp_path: Path):
    _write_finding(tmp_path, "10.10.10.1", "network", "f1")

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_generate_report",
                {"output_base": str(tmp_path), "target": "10.10.10.1", "report_type": "executive"},
            )
            assert result.isError is False
            assert "Executive Summary" in result.structuredContent["content"]

    _run(_go)


def test_generate_report_rejects_invalid_report_type_via_schema_validation(tmp_path: Path):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_generate_report",
                {
                    "output_base": str(tmp_path),
                    "target": "10.10.10.1",
                    "report_type": "not_a_real_type",
                },
            )
            assert result.isError is True
            assert "Input validation error" in result.content[0].text

    _run(_go)
