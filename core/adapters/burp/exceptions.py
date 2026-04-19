"""Burp MCP integration exception hierarchy."""

from __future__ import annotations


class BurpMcpError(RuntimeError):
    """Base Burp MCP integration error."""


class BurpNotReachableError(BurpMcpError):
    """Burp MCP server is not reachable."""


class BurpSseProtocolError(BurpMcpError):
    """Malformed or unexpected SSE protocol behavior."""


class BurpMalformedEventError(BurpMcpError):
    """SSE event payload could not be parsed safely."""


class BurpJsonRpcError(BurpMcpError):
    """JSON-RPC error returned by MCP server."""


class BurpResponseTimeoutError(BurpMcpError):
    """Timed out waiting for JSON-RPC response."""


class BurpUnsupportedCapabilityError(BurpMcpError):
    """Requested capability is not supported by policy or server."""


class BurpNoCapabilitiesError(BurpMcpError):
    """Burp reachable but returned no capabilities."""
