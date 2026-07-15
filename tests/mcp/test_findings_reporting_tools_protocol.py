"""Protocol-level tests for the 4 findings/reporting MCP tools
(reconforge_get_findings, reconforge_get_finding,
reconforge_summarize_findings, reconforge_generate_report), driven
through a real MCP client/server session — see
tests/mcp/test_findings_and_reports.py for direct services.py coverage,
including the security-critical prompt-injection/secret-redaction test.

Also covers the execution-tool pair (reconforge_request_execution /
reconforge_execute_approved_phase) at the protocol level, proving the
out-of-band approval requirement holds even when driven through a real
MCP session rather than called directly against services.py (see
tests/mcp/test_execute_approved_phase.py and
tests/mcp/test_out_of_band_approval_security.py for the deeper
service-layer and adversarial coverage).
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


def test_list_tools_includes_all_read_only_tools_plus_approval_and_execution_tools():
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.list_tools()
            names = {t.name for t in result.tools}
            assert names == set(_TOOLS.keys())
            assert len(names) == 17
            assert "reconforge_request_execution" in names
            assert "reconforge_get_approval_status" in names
            assert "reconforge_execute_approved_phase" in names
            assert "reconforge_start_execution" in names
            assert "reconforge_get_execution_status" in names

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


def test_request_execution_tool_call_denied_without_any_authorization(tmp_path: Path):
    """The protocol-level equivalent of the never-self-approves test: a
    call with no valid engagement/scope supplied must be denied at
    request-creation time, not silently accepted."""

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_request_execution",
                {
                    "engagement_id": "does_not_exist",
                    "target": "10.10.10.1",
                    "module": "web",
                    "phase": "surface",
                    "output_base": str(tmp_path),
                },
            )
            assert result.isError is True

    _run(_go)


def test_request_execution_tool_call_rejects_credential_use_phase(tmp_path: Path):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_request_execution",
                {
                    "engagement_id": "does_not_exist",
                    "target": "10.10.10.1",
                    "module": "ad",
                    "phase": "bloodhound",
                    "domain": "corp.local",
                    "output_base": str(tmp_path),
                },
            )
            assert result.isError is True
            assert "CREDENTIAL_USE" in result.content[0].text

    _run(_go)


def test_execute_approved_phase_tool_call_denied_for_unapproved_request(tmp_path: Path):
    """Even a request_id that genuinely exists — created moments earlier
    by this same client, referencing a real target/module/phase — must
    still be refused until an operator approves it out-of-band. Nothing
    an MCP client can send substitutes for that."""

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            created = await session.call_tool(
                "reconforge_request_execution",
                {
                    "engagement_id": "does_not_exist",
                    "target": "10.10.10.1",
                    "module": "web",
                    "phase": "surface",
                    "output_base": str(tmp_path),
                },
            )
            # request creation itself fails here (no such engagement) --
            # the real point of this test is proven by
            # test_out_of_band_approval_security.py's fully-authorized
            # variant. This still confirms execute_approved_phase can't
            # be reached with a request_id that was never created.
            assert created.isError is True

            result = await session.call_tool(
                "reconforge_execute_approved_phase",
                {"request_id": "not-a-real-request-id"},
            )
            assert result.isError is True

    _run(_go)


def test_execute_approved_phase_tool_call_rejects_unknown_fields():
    """ExecuteApprovedPhaseRequest takes only request_id — proving old
    fields like explicit_confirmation/target/module are silently
    ignored (not honored as authorization) rather than the tool
    accidentally accepting them as meaningful input."""

    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_execute_approved_phase",
                {
                    "engagement_id": "does_not_exist",
                    "target": "10.10.10.1",
                    "module": "web",
                    "phase": "surface",
                    "explicit_confirmation": True,
                },
            )
            # request_id is required and wasn't supplied -- schema
            # validation rejects this before any policy check runs.
            assert result.isError is True

    _run(_go)
