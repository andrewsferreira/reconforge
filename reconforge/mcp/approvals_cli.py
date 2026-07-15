"""CLI surface for out-of-band MCP execution approvals.

This module is the *only* code path in the whole codebase that can
move an :class:`reconforge.mcp.approvals.ApprovalRequest` out of
``awaiting_operator_approval`` — nothing here is reachable through the
MCP protocol, and nothing in ``reconforge/mcp/tools.py`` imports it.
An operator runs these commands directly in their own terminal,
entirely outside whatever process is running ``reconforge mcp serve``.
"""

from __future__ import annotations

import argparse
import json
import sys

from reconforge.mcp import approvals
from reconforge.mcp.errors import MCPServiceError


def add_approvals_subparser(mcp_subparsers: argparse._SubParsersAction) -> None:
    approvals_parser = mcp_subparsers.add_parser(
        "approvals",
        help="Review and act on out-of-band MCP execution approval requests",
        description="Every reconforge_request_execution call from an MCP client only ever "
        "creates a request here in 'awaiting_operator_approval' status — nothing in the MCP "
        "protocol can move it further. Use these commands, run directly in your own terminal, "
        "to review and approve or deny what an MCP client is asking to run.",
    )
    approvals_sub = approvals_parser.add_subparsers(dest="approvals_command", help="Approvals subcommand")

    approvals_sub.add_parser("list", help="List all approval requests, newest last")

    inspect_parser = approvals_sub.add_parser("inspect", help="Show full detail for one approval request")
    inspect_parser.add_argument("request_id")

    approve_parser = approvals_sub.add_parser("approve", help="Approve a pending approval request")
    approve_parser.add_argument("request_id")

    deny_parser = approvals_sub.add_parser("deny", help="Deny a pending approval request")
    deny_parser.add_argument("request_id")
    deny_parser.add_argument("--reason", default=None, help="Optional reason recorded on the request")

    revoke_parser = approvals_sub.add_parser(
        "revoke", help="Revoke a request that was approved but not yet consumed by an execution"
    )
    revoke_parser.add_argument("request_id")

    cleanup_parser = approvals_sub.add_parser(
        "cleanup",
        help="Delete terminal-state (denied/expired/consumed/revoked) request records "
        "older than the retention window — pending/approved-unconsumed requests are never touched",
    )
    cleanup_parser.add_argument(
        "--retention-hours",
        type=int,
        default=None,
        help="Override mcp.approval_retention_hours (default: 24) for this run only",
    )


_LIST_COLUMNS = ("request_id", "status", "module", "phase", "target", "tier", "created_at")


def dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    command = getattr(args, "approvals_command", None)
    try:
        if command == "list":
            _cmd_list()
        elif command == "inspect":
            _cmd_inspect(args.request_id)
        elif command == "approve":
            _cmd_approve(args.request_id)
        elif command == "deny":
            _cmd_deny(args.request_id, args.reason)
        elif command == "revoke":
            _cmd_revoke(args.request_id)
        elif command == "cleanup":
            _cmd_cleanup(args.retention_hours)
        else:
            parser.error(
                "mcp approvals requires a supported subcommand "
                "(list, inspect, approve, deny, revoke, cleanup)"
            )
    except MCPServiceError as exc:
        print(f"Error [{exc.code}]: {exc}", file=sys.stderr)
        sys.exit(1)


def _cmd_list() -> None:
    requests = approvals.list_requests()
    if not requests:
        print("No approval requests found.")
        return
    widths = {col: len(col) for col in _LIST_COLUMNS}
    rows = []
    for record in requests:
        row = {
            "request_id": record.request_id,
            "status": record.status,
            "module": record.module,
            "phase": record.phase,
            "target": record.target,
            "tier": record.tier,
            "created_at": record.created_at,
        }
        rows.append(row)
        for col in _LIST_COLUMNS:
            widths[col] = max(widths[col], len(row[col]))

    header = "  ".join(col.upper().ljust(widths[col]) for col in _LIST_COLUMNS)
    print(header)
    print("-" * len(header))
    for row in rows:
        print("  ".join(row[col].ljust(widths[col]) for col in _LIST_COLUMNS))


def _cmd_inspect(request_id: str) -> None:
    record = approvals.get_request(request_id)
    print(json.dumps(record.to_dict(), indent=2, sort_keys=True))


def _cmd_approve(request_id: str) -> None:
    record = approvals.approve(request_id)
    print(f"Approved {record.request_id} ({record.module}/{record.phase} against {record.target}).")
    print(f"Status: {record.status} | approved_by: {record.approved_by} | expires_at: {record.expires_at}")


def _cmd_deny(request_id: str, reason: str | None) -> None:
    record = approvals.deny(request_id, reason=reason)
    print(f"Denied {record.request_id}. Reason: {record.denial_reason}")


def _cmd_revoke(request_id: str) -> None:
    record = approvals.revoke(request_id)
    print(f"Revoked {record.request_id}. Status: {record.status}")


def _cmd_cleanup(retention_hours: int | None) -> None:
    purged = approvals.purge_terminal_requests(retention_hours=retention_hours)
    if not purged:
        print("No terminal-state requests old enough to purge.")
        return
    print(f"Purged {len(purged)} terminal-state request(s):")
    for request_id in purged:
        print(f"  {request_id}")
