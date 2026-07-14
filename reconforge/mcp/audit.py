"""Structured audit events for MCP tool calls and resource reads.

One JSON line is emitted to stderr for every call to any of the 15 MCP
tools, success or failure — wired into the single choke point every
call already passes through (``reconforge/mcp/tools.py::_call_tool``),
rather than instrumented per tool. ``reconforge/mcp/resources.py``'s
``read_resource`` handler emits an analogous event through the same
stderr channel.

stderr, not a file: this is exactly what the MCP stdio transport
convention reserves stderr for (stdout is exclusively the JSON-RPC
channel — see ``server.py::run_stdio_async()``'s redirect, required for
the same reason). It needs no config and no request-controlled
filesystem path to work correctly, and MCP clients (Claude Desktop,
Claude Code) already capture a server's stderr as logs.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any

from core.logger import sanitize_log

# Never logged verbatim, regardless of value — an approval_id is a
# bearer-token-like authorization reference, not a password, but there's
# no reason to put it in a log stream at all.
_REDACTED_ARGUMENT_KEYS = frozenset({"approval_id"})


def _sanitize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in arguments.items():
        if key in _REDACTED_ARGUMENT_KEYS:
            sanitized[key] = "***REDACTED***" if value else value
        elif isinstance(value, str):
            sanitized[key] = sanitize_log(value)
        else:
            sanitized[key] = value
    return sanitized


def emit_tool_call_audit_event(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    outcome: str,
    error_code: str | None = None,
) -> None:
    """Write one structured JSON audit line to stderr.

    ``outcome`` is ``"success"`` or ``"error"``; ``error_code`` is the
    raising ``MCPServiceError`` subclass's ``code`` (see
    ``reconforge/mcp/errors.py``) when ``outcome == "error"``.
    """
    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "mcp_tool_call",
        "tool": tool_name,
        "outcome": outcome,
        "arguments": _sanitize_arguments(arguments),
    }
    if error_code is not None:
        event["error_code"] = error_code
    print(json.dumps(event, default=str), file=sys.stderr, flush=True)


def emit_resource_read_audit_event(
    uri: str,
    *,
    outcome: str,
    error_code: str | None = None,
) -> None:
    """Write one structured JSON audit line to stderr for a resource read.

    Mirrors ``emit_tool_call_audit_event`` for ``reconforge/mcp/resources.py``'s
    ``read_resource`` handler; ``uri`` is always one of a hardcoded
    allowlist (see ``resources.py``), never client-supplied free text, so
    no sanitization pass is needed here.
    """
    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "mcp_resource_read",
        "uri": uri,
        "outcome": outcome,
    }
    if error_code is not None:
        event["error_code"] = error_code
    print(json.dumps(event, default=str), file=sys.stderr, flush=True)
