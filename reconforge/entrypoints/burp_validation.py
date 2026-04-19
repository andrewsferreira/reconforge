"""Official Burp MCP provider validation entrypoint for ReconForge."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.adapters.burp.config import BurpMcpConfig
from core.adapters.burp.exceptions import (
    BurpMcpError,
    BurpNoCapabilitiesError,
    BurpNotReachableError,
    BurpResponseTimeoutError,
    BurpSseProtocolError,
    BurpUnsupportedCapabilityError,
)
from core.adapters.burp.models import NormalizedBurpHttpRecord
from core.adapters.burp.provider import BurpMcpProvider

LOGGER = logging.getLogger(__name__)

READY = "READY"
PARTIAL = "PARTIAL"
FAILED = "FAILED"


@dataclass
class BurpValidationResult:
    """Structured validation result for Burp MCP provider readiness."""

    generated_at: str
    provider_name: str = "burp_mcp"
    provider_type: str = "mcp_adapter"
    provider_url: str = ""
    connection_status: str = "DISCONNECTED"
    session_status: str = "NOT_ESTABLISHED"
    session_id: str = ""
    capability_discovery_status: str = "NOT_RUN"
    total_tools: int = 0
    discovered_tools: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)
    safe_test_name: str = ""
    safe_test_status: str = "NOT_RUN"
    safe_test_latency_ms: float = 0.0
    safe_test_summary: str = ""
    normalized_record_count: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    readiness_status: str = FAILED

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return float(raw)


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return int(raw)


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def build_burp_config(
    base_url: str | None = None,
    rpc_timeout_seconds: float | None = None,
    connect_timeout_seconds: float | None = None,
    debug_logging: bool | None = None,
) -> BurpMcpConfig:
    """Build Burp config aligned to ReconForge environment conventions."""
    return BurpMcpConfig(
        base_url=base_url or os.getenv("BURP_MCP_URL", "http://127.0.0.1:9876"),
        rpc_timeout_seconds=(
            rpc_timeout_seconds if rpc_timeout_seconds is not None else _float_env("BURP_MCP_RPC_TIMEOUT_SECONDS", 8.0)
        ),
        connect_timeout_seconds=(
            connect_timeout_seconds
            if connect_timeout_seconds is not None
            else _float_env("BURP_MCP_CONNECT_TIMEOUT_SECONDS", 3.0)
        ),
        read_timeout_seconds=_float_env("BURP_MCP_READ_TIMEOUT_SECONDS", 30.0),
        max_retries=_int_env("BURP_MCP_MAX_RETRIES", 2),
        debug_logging=debug_logging if debug_logging is not None else _bool_env("BURP_MCP_DEBUG", False),
    )


def _validate_normalized_records(records: Any) -> tuple[bool, str, int]:
    if not isinstance(records, list):
        return False, "Safe test returned malformed payload (expected list).", 0

    normalized = all(isinstance(record, NormalizedBurpHttpRecord) for record in records)
    if not normalized:
        return False, "Safe test returned non-normalized records.", len(records)

    if len(records) == 0:
        return True, "Safe probe succeeded; proxy history is currently empty (valid).", 0
    return True, f"Safe probe succeeded with {len(records)} normalized record(s).", len(records)


def _pick_safe_test_tool(allowed_tools: list[str]) -> str:
    for candidate in ("get_proxy_http_history", "get_proxy_http_history_regex"):
        if candidate in allowed_tools:
            return candidate
    return ""


def _compute_readiness(result: BurpValidationResult) -> str:
    if result.connection_status != "CONNECTED" or result.session_status != "ESTABLISHED":
        return FAILED
    if result.capability_discovery_status != "SUCCESS":
        return PARTIAL
    if result.safe_test_status != "SUCCESS":
        return PARTIAL
    return READY


def validate_burp_provider(
    base_url: str | None = None,
    rpc_timeout_seconds: float | None = None,
    connect_timeout_seconds: float | None = None,
    debug_logging: bool | None = None,
) -> BurpValidationResult:
    """Validate Burp MCP provider readiness through provider abstraction only."""
    config = build_burp_config(
        base_url=base_url,
        rpc_timeout_seconds=rpc_timeout_seconds,
        connect_timeout_seconds=connect_timeout_seconds,
        debug_logging=debug_logging,
    )
    result = BurpValidationResult(generated_at=_now_utc_iso(), provider_url=config.base_url)
    provider = BurpMcpProvider(config=config)

    LOGGER.info(json.dumps({"event": "burp_validation_start", "provider_url": config.base_url}))

    try:
        state = provider.start()

        result.connection_status = "CONNECTED" if state.session.sse_connected else "DISCONNECTED"
        result.session_id = state.session.session_id
        result.session_status = "ESTABLISHED" if state.session.session_id else "MISSING_SESSION_ID"

        result.discovered_tools = sorted(cap.name for cap in state.discovered_tools)
        result.total_tools = len(result.discovered_tools)
        result.allowed_tools = sorted(state.enabled_tools)
        result.blocked_tools = sorted(state.disabled_tools)

        if result.total_tools == 0:
            raise BurpNoCapabilitiesError("tools/list returned an empty tool set")

        result.capability_discovery_status = "SUCCESS"
        if not result.session_id:
            result.warnings.append("sessionId missing from SSE metadata")

        safe_tool = _pick_safe_test_tool(result.allowed_tools)
        if not safe_tool:
            result.safe_test_status = "DENIED_BY_POLICY"
            result.safe_test_summary = "No approved safe validation tool available in allowed capability set."
            result.warnings.append(result.safe_test_summary)
            result.readiness_status = _compute_readiness(result)
            return result

        result.safe_test_name = safe_tool
        started = time.perf_counter()

        if safe_tool == "get_proxy_http_history":
            payload = provider.get_proxy_http_history({})
        else:
            payload = provider.get_proxy_http_history_regex({"regex": ".*"})

        result.safe_test_latency_ms = round((time.perf_counter() - started) * 1000, 2)
        ok, summary, count = _validate_normalized_records(payload)
        result.normalized_record_count = count
        result.safe_test_status = "SUCCESS" if ok else "FAILED"
        result.safe_test_summary = summary
        if not ok:
            result.errors.append(summary)

    except BurpNotReachableError as exc:
        result.connection_status = "UNREACHABLE"
        result.session_status = "FAILED"
        result.capability_discovery_status = "FAILED"
        result.safe_test_status = "NOT_RUN"
        result.errors.append(f"Burp MCP not reachable: {exc}")
    except BurpSseProtocolError as exc:
        result.connection_status = "CONNECTED"
        result.session_status = "FAILED"
        result.capability_discovery_status = "FAILED"
        result.safe_test_status = "NOT_RUN"
        result.errors.append(f"SSE/session initialization failure: {exc}")
    except BurpResponseTimeoutError as exc:
        if result.connection_status == "DISCONNECTED":
            result.connection_status = "CONNECTED"
        if result.capability_discovery_status == "NOT_RUN":
            result.capability_discovery_status = "PARTIAL"
        result.safe_test_status = "TIMEOUT"
        result.errors.append(f"Provider timeout: {exc}")
    except BurpNoCapabilitiesError as exc:
        result.capability_discovery_status = "FAILED"
        result.safe_test_status = "NOT_RUN"
        result.errors.append(f"Capability discovery failure: {exc}")
    except BurpUnsupportedCapabilityError as exc:
        result.safe_test_status = "DENIED_BY_POLICY"
        result.errors.append(f"Safe test denied by policy: {exc}")
    except BurpMcpError as exc:
        if result.capability_discovery_status == "NOT_RUN":
            result.capability_discovery_status = "FAILED"
        if result.safe_test_status == "NOT_RUN":
            result.safe_test_status = "FAILED"
        result.errors.append(f"Provider call failure: {exc}")
    except Exception as exc:  # noqa: BLE001
        result.safe_test_status = "FAILED"
        result.errors.append(f"Unexpected validation failure: {exc}")
    finally:
        provider.stop()

    result.readiness_status = _compute_readiness(result)
    LOGGER.info(
        json.dumps(
            {
                "event": "burp_validation_complete",
                "provider_url": result.provider_url,
                "connection_status": result.connection_status,
                "session_status": result.session_status,
                "capability_discovery_status": result.capability_discovery_status,
                "safe_test_status": result.safe_test_status,
                "readiness_status": result.readiness_status,
            }
        )
    )
    return result


def render_validation_console_summary(result: BurpValidationResult) -> str:
    """Render human-readable Burp validation output."""
    lines = [
        "Burp MCP Validation Summary",
        "=" * 28,
        f"Provider: {result.provider_name} ({result.provider_type})",
        f"Provider URL: {result.provider_url}",
        f"Connection: {result.connection_status}",
        f"Session: {result.session_status} (session_id={result.session_id or '<missing>'})",
        f"Capability discovery: {result.capability_discovery_status}",
        f"Total tools discovered: {result.total_tools}",
        f"Allowed tools ({len(result.allowed_tools)}): {', '.join(result.allowed_tools) or '<none>'}",
        f"Blocked tools ({len(result.blocked_tools)}): {', '.join(result.blocked_tools) or '<none>'}",
        f"Safe test: {result.safe_test_name or '<none>'}",
        f"Safe test status: {result.safe_test_status}",
        f"Safe test latency (ms): {result.safe_test_latency_ms}",
        f"Safe test summary: {result.safe_test_summary or '<none>'}",
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
