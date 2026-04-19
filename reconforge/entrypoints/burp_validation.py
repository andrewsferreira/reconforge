"""Official Burp MCP provider validation entrypoint for ReconForge."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from core.adapters.burp.config import BurpMcpConfig
from core.adapters.burp.exceptions import (
    BurpMcpError,
    BurpNoCapabilitiesError,
    BurpNotReachableError,
    BurpResponseTimeoutError,
    BurpSseProtocolError,
)
from core.adapters.burp.provider import BurpMcpProvider

LOGGER = logging.getLogger(__name__)

READY = "READY"
PARTIAL = "PARTIAL"
FAILED = "FAILED"


@dataclass
class BurpValidationResult:
    generated_at: str
    provider_url: str
    connection_status: str = "DISCONNECTED"
    session_id: str = ""
    total_tools: int = 0
    allowed_tools: List[str] = field(default_factory=list)
    blocked_tools: List[str] = field(default_factory=list)
    test_tool: str = ""
    test_execution_success: bool = False
    test_execution_latency: float = 0.0
    normalized_record_count: int = 0
    readiness_status: str = FAILED
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_burp_config_from_env(base_url: str | None = None) -> BurpMcpConfig:
    """Build Burp MCP config with environment override support."""
    configured_url = base_url or os.getenv("BURP_MCP_URL", "http://127.0.0.1:9876")
    return BurpMcpConfig(base_url=configured_url)


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_normalized_records(records: Any) -> bool:
    if not isinstance(records, list):
        return False
    return all(hasattr(record, "tool_name") and hasattr(record, "provider") for record in records)


def _pick_safe_test_tool(allowed_tools: List[str]) -> str:
    for candidate in ("get_proxy_http_history", "get_proxy_http_history_regex"):
        if candidate in allowed_tools:
            return candidate
    return ""


def validate_burp_provider(base_url: str | None = None) -> BurpValidationResult:
    """Validate Burp MCP provider connectivity, capabilities, and a safe execution flow."""
    config = build_burp_config_from_env(base_url=base_url)
    result = BurpValidationResult(generated_at=_now_utc_iso(), provider_url=config.base_url)
    provider = BurpMcpProvider(config=config)

    LOGGER.info(json.dumps({"event": "burp_validation_connection_start", "base_url": config.base_url}))

    try:
        state = provider.start()
        result.connection_status = "CONNECTED" if state.session.sse_connected else "DISCONNECTED"
        result.session_id = state.session.session_id
        result.total_tools = len(state.discovered_tools)
        result.allowed_tools = sorted(state.enabled_tools)
        result.blocked_tools = sorted(state.disabled_tools)

        LOGGER.info(
            json.dumps(
                {
                    "event": "burp_validation_session_acquired",
                    "session_id": result.session_id,
                    "message_endpoint": state.session.message_endpoint,
                }
            )
        )
        LOGGER.info(
            json.dumps(
                {
                    "event": "burp_validation_tools_discovered",
                    "total_tools": result.total_tools,
                    "allowed_tools": result.allowed_tools,
                    "blocked_tools": result.blocked_tools,
                }
            )
        )

        if not state.session.session_id:
            result.warnings.append("sessionId missing from SSE metadata")
        if result.total_tools == 0:
            raise BurpNoCapabilitiesError("tools/list returned an empty tool set")

        result.test_tool = _pick_safe_test_tool(result.allowed_tools)
        if not result.test_tool:
            result.warnings.append("No safe tool enabled by policy for execution probe")
            result.readiness_status = PARTIAL
            return result

        LOGGER.info(json.dumps({"event": "burp_validation_test_execution_start", "tool": result.test_tool}))
        started = time.perf_counter()

        if result.test_tool == "get_proxy_http_history":
            normalized = provider.get_proxy_http_history({})
        else:
            normalized = provider.get_proxy_http_history_regex({"regex": ".*"})

        result.test_execution_latency = round((time.perf_counter() - started) * 1000, 2)
        result.normalized_record_count = len(normalized) if isinstance(normalized, list) else 0

        result.test_execution_success = _validate_normalized_records(normalized)
        if not result.test_execution_success:
            result.errors.append("Safe test execution returned non-normalized response structure")

        LOGGER.info(
            json.dumps(
                {
                    "event": "burp_validation_test_execution_result",
                    "tool": result.test_tool,
                    "success": result.test_execution_success,
                    "latency_ms": result.test_execution_latency,
                    "normalized_record_count": result.normalized_record_count,
                }
            )
        )

        if result.connection_status == "CONNECTED" and result.total_tools > 0 and result.test_execution_success:
            result.readiness_status = READY
        elif result.connection_status == "CONNECTED":
            result.readiness_status = PARTIAL
        else:
            result.readiness_status = FAILED

    except BurpNotReachableError as exc:
        result.errors.append(f"Burp MCP not reachable: {exc}")
        result.readiness_status = FAILED
    except BurpSseProtocolError as exc:
        result.errors.append(f"SSE connection failure: {exc}")
        result.readiness_status = FAILED
    except BurpResponseTimeoutError as exc:
        result.errors.append(f"Timeout waiting for SSE/JSON-RPC response: {exc}")
        result.readiness_status = PARTIAL
    except BurpNoCapabilitiesError as exc:
        result.errors.append(f"Capability discovery failed: {exc}")
        result.readiness_status = PARTIAL if result.connection_status == "CONNECTED" else FAILED
    except BurpMcpError as exc:
        result.errors.append(f"Burp provider validation failed: {exc}")
        result.readiness_status = PARTIAL if result.connection_status == "CONNECTED" else FAILED
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"Unexpected validation failure: {exc}")
        result.readiness_status = FAILED
    finally:
        provider.stop()

    return result


def render_validation_console_summary(result: BurpValidationResult) -> str:
    """Render a human-friendly validation summary."""
    lines = [
        "Burp MCP Validation Summary",
        "=" * 28,
        f"Provider URL: {result.provider_url}",
        f"Connection status: {result.connection_status}",
        f"Session ID: {result.session_id or '<missing>'}",
        f"Total tools discovered: {result.total_tools}",
        f"Allowed tools ({len(result.allowed_tools)}): {', '.join(result.allowed_tools) or '<none>'}",
        f"Blocked tools ({len(result.blocked_tools)}): {', '.join(result.blocked_tools) or '<none>'}",
        f"Safe test tool: {result.test_tool or '<none>'}",
        f"Safe test success: {result.test_execution_success}",
        f"Safe test latency (ms): {result.test_execution_latency}",
        f"Readiness status: {result.readiness_status}",
    ]

    if result.warnings:
        lines.append(f"Warnings: {'; '.join(result.warnings)}")
    if result.errors:
        lines.append(f"Errors: {'; '.join(result.errors)}")

    return "\n".join(lines)


def save_validation_json(result: BurpValidationResult, output_path: str | Path) -> Path:
    """Persist structured validation output to JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return path
