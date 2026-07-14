"""Registers ReconForge's read-only MCP resources onto a ``Server``
instance.

Resources are MCP's second content-exposure primitive, distinct from
tools: a client lists and reads them without constructing call
arguments, which suits ambient reference material (documentation, a
live module catalog) better than an invoked, parameterized call. Every
resource this module serves comes from an explicit, hardcoded
allowlist keyed by a ``reconforge://`` URI — never a filesystem walk,
a glob, or any part of a client-supplied path — so a ``read_resource``
call can never reach a file outside the small, named set below.
"""

from __future__ import annotations

from pathlib import Path

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from pydantic import AnyUrl

from reconforge.mcp import schemas, services
from reconforge.mcp.audit import emit_resource_read_audit_event
from reconforge.mcp.errors import MCPServiceError

_DOCS_DIR = Path(__file__).resolve().parents[2] / "docs"

# uri -> (filename under docs/, display name, description)
_DOC_RESOURCES: dict[str, tuple[str, str, str]] = {
    "reconforge://docs/claude-mcp-integration": (
        "CLAUDE_MCP_INTEGRATION.md",
        "Claude MCP Integration Guide",
        "How to connect Claude Desktop/Code to this MCP server, its "
        "security model, and the full tool reference.",
    ),
    "reconforge://docs/architecture": (
        "ARCHITECTURE.md",
        "ReconForge Architecture",
        "System architecture: modules, core services, and execution flow.",
    ),
    "reconforge://docs/modules": (
        "MODULES.md",
        "Module Reference",
        "Narrative reference for all five ReconForge modules and their phases.",
    ),
    "reconforge://docs/configuration": (
        "CONFIGURATION.md",
        "Configuration Reference",
        "config.yaml / opsec.yaml / mcp.yaml structure and fields.",
    ),
    "reconforge://docs/findings": (
        "FINDINGS.md",
        "Findings Schema",
        "Finding fields, severity/confidence taxonomy, and storage format.",
    ),
    "reconforge://docs/limitations": (
        "LIMITATIONS.md",
        "Known Limitations",
        "Documented gaps and non-goals -- what ReconForge deliberately does not do.",
    ),
}

_MODULES_URI = "reconforge://modules"

_ALL_URIS = frozenset({*_DOC_RESOURCES, _MODULES_URI})


def register(server: Server) -> None:
    """Attach the read-only resource handlers to *server*."""

    @server.list_resources()
    async def _list_resources() -> list[types.Resource]:
        resources = [
            types.Resource(
                uri=AnyUrl(uri),
                name=name,
                description=description,
                mimeType="text/markdown",
            )
            for uri, (_filename, name, description) in _DOC_RESOURCES.items()
        ]
        resources.append(
            types.Resource(
                uri=AnyUrl(_MODULES_URI),
                name="Module Catalog",
                description=(
                    "Live JSON list of the five ReconForge modules, their valid "
                    "phases, wrapped tools, and opt-in capabilities -- the same "
                    "data as the reconforge_list_modules tool."
                ),
                mimeType="application/json",
            )
        )
        return resources

    @server.read_resource()
    async def _read_resource(uri: AnyUrl) -> list[ReadResourceContents]:
        uri_str = str(uri)
        try:
            if uri_str not in _ALL_URIS:
                raise MCPServiceError(f"Unknown resource: {uri_str}")
            if uri_str == _MODULES_URI:
                response = services.list_modules(schemas.ListModulesRequest())
                contents = [
                    ReadResourceContents(
                        content=response.model_dump_json(), mime_type="application/json"
                    )
                ]
            else:
                filename, _name, _description = _DOC_RESOURCES[uri_str]
                content = (_DOCS_DIR / filename).read_text(encoding="utf-8")
                contents = [ReadResourceContents(content=content, mime_type="text/markdown")]
        except MCPServiceError as exc:
            emit_resource_read_audit_event(uri_str, outcome="error", error_code=exc.code)
            raise
        emit_resource_read_audit_event(uri_str, outcome="success")
        return contents
