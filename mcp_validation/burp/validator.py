"""Burp MCP validation workflow based on integrated core provider."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from core.adapters.burp.capabilities import SAFE_EXPOSED_TOOLS
from core.adapters.burp.exceptions import BurpMcpError, BurpNoCapabilitiesError
from core.adapters.burp.provider import BurpMcpProvider

from mcp_validation.burp.models import SafeExecutionResult, ValidationConfig, ValidationError, ValidationReport

LOGGER = logging.getLogger(__name__)


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class BurpMcpValidator:
    def __init__(self, config: ValidationConfig | None = None):
        self.config = config or ValidationConfig()
        self.provider = BurpMcpProvider(config=self.config)

    def run(self) -> ValidationReport:
        errors: List[ValidationError] = []
        missing: List[str] = []
        restricted: List[str] = []
        notes: List[str] = []
        safe_execution = SafeExecutionResult()

        try:
            state = self.provider.start()
        except BurpMcpError as exc:
            errors.append(self._err("connection", exc, recoverable=False))
            return ValidationReport(
                generated_at=now_utc_iso(),
                target_url=self.config.base_url,
                success=False,
                recommendation="NOT READY",
                connection=self.provider.state.session,
                tool_count=0,
                tools=[],
                missing_features=["tools/list", "tools/call", "session stability"],
                restricted_features=[],
                safe_execution=safe_execution,
                errors=errors,
                notes=["Burp MCP endpoint unreachable or refused connection."],
            )

        tools = state.discovered_tools
        if not tools:
            errors.append(self._err("capability_discovery", BurpNoCapabilitiesError("no capabilities"), recoverable=False))
            missing.append("tools/list returned empty set")

        # Record disabled tools as restricted by default policy.
        for tool in state.discovered_tools:
            if not tool.enabled:
                restricted.append(f"{tool.name}: {tool.reason}")

        safe_tool = self._pick_safe_tool(state.enabled_tools)
        if safe_tool:
            safe_execution = self._execute_safe_tool(safe_tool)
        else:
            restricted.append("No safe allowed tool available for execution test")

        self.provider.stop()

        success = state.session.sse_connected and bool(tools) and safe_execution.success
        recommendation = self._recommendation(success, tools, safe_execution, errors)

        if not state.session.session_id:
            notes.append("No explicit sessionId observed; server may operate statelessly or hide session metadata.")
        if state.session.message_endpoint.endswith(self.config.message_path_fallback):
            notes.append("Using fallback message endpoint; server did not emit endpoint hint event.")

        return ValidationReport(
            generated_at=now_utc_iso(),
            target_url=self.config.base_url,
            success=success,
            recommendation=recommendation,
            connection=state.session,
            tool_count=len(tools),
            tools=tools,
            missing_features=missing,
            restricted_features=restricted,
            safe_execution=safe_execution,
            errors=errors,
            notes=notes,
        )

    def save_report(self, report: ValidationReport, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        return path

    def _execute_safe_tool(self, tool_name: str) -> SafeExecutionResult:
        started = time.time()
        result = SafeExecutionResult(tool_name=tool_name, attempted=True)
        try:
            # empty-argument safe probe for validation only
            if tool_name == "get_proxy_http_history":
                _ = self.provider.get_proxy_http_history({})
            elif tool_name == "get_proxy_http_history_regex":
                _ = self.provider.get_proxy_http_history_regex({"regex": ".*"})
            elif tool_name == "send_http1_request":
                _ = self.provider.send_http1_request({})
            elif tool_name == "send_http2_request":
                _ = self.provider.send_http2_request({})
            else:
                raise BurpMcpError(f"Unsupported safe validation tool: {tool_name}")
            result.success = True
            result.response_shape_valid = True
        except Exception as exc:  # noqa: BLE001
            result.success = False
            result.error = str(exc)
        finally:
            result.latency_ms = round((time.time() - started) * 1000, 2)
        return result

    def _pick_safe_tool(self, enabled_tools: List[str]) -> str:
        for candidate in ("get_proxy_http_history", "get_proxy_http_history_regex", "send_http1_request", "send_http2_request"):
            if candidate in enabled_tools:
                return candidate
        return ""

    def _err(self, stage: str, exc: Exception, recoverable: bool) -> ValidationError:
        LOGGER.error(json.dumps({"event": "burp_validation_error", "stage": stage, "error": str(exc)}))
        return ValidationError(stage=stage, error_type=type(exc).__name__, message=str(exc), recoverable=recoverable)

    @staticmethod
    def _recommendation(success: bool, tools: List, safe_execution: SafeExecutionResult, errors: List[ValidationError]) -> str:
        if success:
            return "READY for ReconForge integration"
        if tools and not safe_execution.success:
            return "PARTIAL support"
        if errors:
            return "NOT READY"
        return "PARTIAL support"
