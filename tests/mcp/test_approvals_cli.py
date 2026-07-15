"""Tests for reconforge/mcp/approvals_cli.py — the only code path in
this codebase that can move an approval request out of
'awaiting_operator_approval'. Deliberately exercised only through
argparse.Namespace + dispatch() here (unit-level), and separately
through a real 'reconforge mcp approvals ...' subprocess invocation in
tests/mcp/test_stdio_transport_integrity.py-adjacent manual verification
— this file's job is to pin down every command's behavior precisely,
including its error handling.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone

import pytest

from reconforge.mcp import approvals, approvals_cli


def _create(**overrides) -> approvals.ApprovalRequest:
    defaults = {
        "engagement_id": "engagement_active",
        "target": "10.10.10.1",
        "normalized_target": "10.10.10.1",
        "module": "surface",
        "phase": "vector_correlation",
        "opsec_profile": "normal",
        "tier": "safe_read_only",
        "scope_reference": "scope.yaml",
        "output_base": "outputs",
        "domain": "",
        "scope_file": None,
        "approval_id": None,
        "timeout": 600,
    }
    defaults.update(overrides)
    return approvals.create_request(**defaults)


def _build_parser() -> tuple[argparse.ArgumentParser, argparse._SubParsersAction]:
    parser = argparse.ArgumentParser(prog="reconforge")
    subparsers = parser.add_subparsers(dest="module")
    mcp_parser = subparsers.add_parser("mcp")
    mcp_subparsers = mcp_parser.add_subparsers(dest="mcp_command")
    approvals_cli.add_approvals_subparser(mcp_subparsers)
    return parser, mcp_subparsers


# ── argument parsing ────────────────────────────────────────────────


def test_add_approvals_subparser_parses_list():
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "list"])
    assert args.approvals_command == "list"


def test_add_approvals_subparser_parses_inspect_with_request_id():
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "inspect", "abc-123"])
    assert args.approvals_command == "inspect"
    assert args.request_id == "abc-123"


def test_add_approvals_subparser_parses_deny_with_optional_reason():
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "deny", "abc-123", "--reason", "nope"])
    assert args.reason == "nope"

    args_no_reason = parser.parse_args(["mcp", "approvals", "deny", "abc-123"])
    assert args_no_reason.reason is None


def test_add_approvals_subparser_parses_cleanup_with_optional_retention_hours():
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "cleanup", "--retention-hours", "72"])
    assert args.approvals_command == "cleanup"
    assert args.retention_hours == 72

    args_default = parser.parse_args(["mcp", "approvals", "cleanup"])
    assert args_default.retention_hours is None


# ── dispatch: list ───────────────────────────────────────────────────


def test_dispatch_list_prints_message_when_empty(capsys: pytest.CaptureFixture[str]):
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "list"])
    approvals_cli.dispatch(args, parser)
    out = capsys.readouterr().out
    assert "No approval requests found." in out


def test_dispatch_list_prints_a_row_per_request(capsys: pytest.CaptureFixture[str]):
    record = _create()
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "list"])
    approvals_cli.dispatch(args, parser)
    out = capsys.readouterr().out
    assert record.request_id in out
    assert "awaiting_operator_approval" in out
    assert "REQUEST_ID" in out  # header row


# ── dispatch: inspect ────────────────────────────────────────────────


def test_dispatch_inspect_prints_full_record_as_json(capsys: pytest.CaptureFixture[str]):
    record = _create()
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "inspect", record.request_id])
    approvals_cli.dispatch(args, parser)
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["request_id"] == record.request_id
    assert parsed["module"] == "surface"


def test_dispatch_inspect_unknown_id_exits_nonzero_with_error(capsys: pytest.CaptureFixture[str]):
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "inspect", "not-a-real-id"])
    with pytest.raises(SystemExit) as exc_info:
        approvals_cli.dispatch(args, parser)
    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "APPROVAL_NOT_FOUND" in err


# ── dispatch: approve / deny / revoke ─────────────────────────────────


def test_dispatch_approve_prints_confirmation_and_updates_status(capsys: pytest.CaptureFixture[str]):
    record = _create()
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "approve", record.request_id])
    approvals_cli.dispatch(args, parser)
    out = capsys.readouterr().out
    assert "Approved" in out
    assert approvals.get_request(record.request_id).status == "approved"


def test_dispatch_approve_already_approved_exits_nonzero(capsys: pytest.CaptureFixture[str]):
    record = _create()
    approvals.approve(record.request_id)
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "approve", record.request_id])
    with pytest.raises(SystemExit) as exc_info:
        approvals_cli.dispatch(args, parser)
    assert exc_info.value.code == 1
    assert "APPROVAL_STATE_ERROR" in capsys.readouterr().err


def test_dispatch_deny_with_reason(capsys: pytest.CaptureFixture[str]):
    record = _create()
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "deny", record.request_id, "--reason", "Out of scope."])
    approvals_cli.dispatch(args, parser)
    out = capsys.readouterr().out
    assert "Out of scope." in out
    assert approvals.get_request(record.request_id).denial_reason == "Out of scope."


def test_dispatch_revoke_an_approved_request(capsys: pytest.CaptureFixture[str]):
    record = _create()
    approvals.approve(record.request_id)
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "revoke", record.request_id])
    approvals_cli.dispatch(args, parser)
    out = capsys.readouterr().out
    assert "Revoked" in out
    assert approvals.get_request(record.request_id).status == "revoked"


def test_dispatch_revoke_never_approved_request_exits_nonzero(capsys: pytest.CaptureFixture[str]):
    record = _create()
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "revoke", record.request_id])
    with pytest.raises(SystemExit) as exc_info:
        approvals_cli.dispatch(args, parser)
    assert exc_info.value.code == 1
    assert "APPROVAL_STATE_ERROR" in capsys.readouterr().err


# ── dispatch: cleanup ────────────────────────────────────────────────


def _backdate_created_at(record: approvals.ApprovalRequest, *, hours_ago: float) -> None:
    path = approvals._request_path(record.request_id)
    data = json.loads(path.read_text())
    data["created_at"] = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
    path.write_text(json.dumps(data))


def test_dispatch_cleanup_prints_no_op_message_when_nothing_to_purge(
    capsys: pytest.CaptureFixture[str],
):
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "cleanup"])
    approvals_cli.dispatch(args, parser)
    out = capsys.readouterr().out
    assert "No terminal-state requests old enough to purge." in out


def test_dispatch_cleanup_purges_old_denied_request_with_explicit_retention(
    capsys: pytest.CaptureFixture[str],
):
    record = _create()
    approvals.deny(record.request_id)
    _backdate_created_at(record, hours_ago=48)

    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "cleanup", "--retention-hours", "24"])
    approvals_cli.dispatch(args, parser)
    out = capsys.readouterr().out
    assert "Purged 1 terminal-state request(s)" in out
    assert record.request_id in out
    assert not approvals._request_path(record.request_id).is_file()


def test_dispatch_cleanup_leaves_pending_requests_alone(capsys: pytest.CaptureFixture[str]):
    record = _create()
    _backdate_created_at(record, hours_ago=999)

    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals", "cleanup", "--retention-hours", "24"])
    approvals_cli.dispatch(args, parser)
    assert "No terminal-state requests old enough to purge." in capsys.readouterr().out
    assert approvals.get_request(record.request_id).status == "awaiting_operator_approval"


# ── dispatch: no subcommand ────────────────────────────────────────────


def test_dispatch_with_no_subcommand_calls_parser_error():
    parser, _ = _build_parser()
    args = parser.parse_args(["mcp", "approvals"])
    with pytest.raises(SystemExit):
        approvals_cli.dispatch(args, parser)
