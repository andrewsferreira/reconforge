"""Burp MCP validation wrappers."""

from mcp_validation.burp.models import ValidationConfig, ValidationReport
from mcp_validation.burp.validator import BurpMcpValidator

__all__ = ["BurpMcpValidator", "ValidationConfig", "ValidationReport"]
