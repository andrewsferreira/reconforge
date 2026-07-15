"""Protocol-level tests for reconforge/mcp/tools.py::_error_result — the
structured error path added so a client can act on ``error_code`` (and,
for policy denials, ``missing_requirements``) instead of parsing the
free-text message. Before this, every ``MCPServiceError`` fell through to
the `mcp` SDK's own generic ``except Exception as e: return
self._make_error_result(str(e))``, which only ever produces plain text —
each subclass's ``code`` class attribute was declared but never actually
reached the client.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import anyio
import yaml
from mcp.shared.memory import create_connected_server_and_client_session

from core.engagement import EngagementManager
from reconforge.mcp import approvals, schemas, services
from reconforge.mcp.server import build_server


def _run(coro_fn):
    anyio.run(coro_fn)


def _save_active_engagement(tmp_path: Path, engagement_id: str = "engagement_active") -> None:
    mgr = EngagementManager(name="Test Engagement", operator="tester", scope=["10.10.10.1"])
    mgr.start()
    workflow_dir = tmp_path / "workflow"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    mgr.save(workflow_dir / f"{engagement_id}.json")


def _write_scope_file(path: Path, targets=("10.10.10.1",), approval_id: str = "APPROVAL-1") -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "allowed_targets": list(targets),
                "approval_id": approval_id,
                "valid_until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            }
        )
    )


def test_unknown_tool_name_returns_structured_generic_code():
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool("reconforge_not_a_real_tool", {})
            assert result.isError is True
            assert result.structuredContent is not None
            assert result.structuredContent["error_code"] == "MCP_SERVICE_ERROR"
            assert "Unknown tool" in result.structuredContent["message"]
            assert "missing_requirements" not in result.structuredContent

    _run(_go)


def test_finding_not_found_returns_structured_code(tmp_path: Path):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_get_finding",
                {"finding_id": "does-not-exist", "output_base": str(tmp_path)},
            )
            assert result.isError is True
            assert result.structuredContent["error_code"] == "FINDING_NOT_FOUND"
            assert "missing_requirements" not in result.structuredContent

    _run(_go)


def test_unknown_phase_returns_structured_code(tmp_path: Path):
    async def _go() -> None:
        server = build_server()
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_request_execution",
                {
                    "engagement_id": "does_not_exist",
                    "target": "10.10.10.1",
                    "module": "web",
                    "phase": "not_a_real_phase",
                    "output_base": str(tmp_path),
                },
            )
            assert result.isError is True
            assert result.structuredContent["error_code"] == "UNKNOWN_PHASE"

    _run(_go)


def test_policy_blocked_without_engagement_surfaces_missing_requirement(tmp_path: Path):
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
            assert result.structuredContent["error_code"] == "POLICY_BLOCKED"
            assert "engagement_id" in result.structuredContent["missing_requirements"]

    _run(_go)


def test_policy_blocked_for_intrusive_without_config_gate_surfaces_missing_requirement(tmp_path: Path):
    """web/exploit is INTRUSIVE-tier — engagement and scope are both
    satisfied here, isolating the server-wide config-gate requirement
    as the only remaining reason the request is denied."""

    async def _go() -> None:
        server = build_server()
        _save_active_engagement(tmp_path)
        scope_file = tmp_path / "scope.yaml"
        _write_scope_file(scope_file)
        async with create_connected_server_and_client_session(server) as session:
            result = await session.call_tool(
                "reconforge_request_execution",
                {
                    "engagement_id": "engagement_active",
                    "target": "10.10.10.1",
                    "module": "web",
                    "phase": "exploit",
                    "output_base": str(tmp_path),
                    "scope_file": str(scope_file),
                    "approval_id": "APPROVAL-1",
                },
            )
            assert result.isError is True
            assert result.structuredContent["error_code"] == "POLICY_BLOCKED"
            missing = result.structuredContent["missing_requirements"]
            assert any("allow_intrusive_execution" in m for m in missing)

    _run(_go)


def test_credential_use_rejection_has_no_missing_requirements(tmp_path: Path):
    """CREDENTIAL_USE is rejected outright before the requirements check
    even runs — there's nothing "missing" the operator could supply to fix
    it, so the key shouldn't appear (as opposed to being present-but-empty)."""

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
            assert result.structuredContent["error_code"] == "POLICY_BLOCKED"
            assert "missing_requirements" not in result.structuredContent

    _run(_go)


def test_execution_conflict_returns_structured_code(tmp_path: Path):
    async def _go() -> None:
        server = build_server()

        # Create and approve a request out-of-band (never through MCP --
        # approvals.approve() is only ever called directly, as the CLI
        # would) so there's a genuinely executable request to attempt.
        _save_active_engagement(tmp_path)
        scope_file = tmp_path / "scope.yaml"
        _write_scope_file(scope_file)
        created = services.request_execution(
            schemas.RequestExecutionRequest(
                engagement_id="engagement_active",
                target="10.10.10.1",
                module="surface",
                phase="vector_correlation",
                output_base=str(tmp_path),
                scope_file=str(scope_file),
                approval_id="APPROVAL-1",
            )
        )
        approvals.approve(created.request_id)

        assert services._EXECUTION_LOCK.acquire(blocking=False)
        try:
            async with create_connected_server_and_client_session(server) as session:
                result = await session.call_tool(
                    "reconforge_execute_approved_phase",
                    {"request_id": created.request_id},
                )
                assert result.isError is True
                assert result.structuredContent["error_code"] == "EXECUTION_CONFLICT"
        finally:
            services._EXECUTION_LOCK.release()

    _run(_go)
