"""Compatibility wrapper to core Burp SSE connection integration."""

from core.adapters.burp.connection import BurpSseConnection, parse_sse_stream_line

__all__ = ["BurpSseConnection", "parse_sse_stream_line"]
