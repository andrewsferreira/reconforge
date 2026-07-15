"""JSON-RPC helpers for Burp MCP provider."""

from __future__ import annotations

import itertools
import json
import logging
from typing import Any

from core.adapters.burp.connection import BurpSseConnection
from core.adapters.burp.exceptions import BurpJsonRpcError
from core.adapters.burp.models import BurpRpcResult

LOGGER = logging.getLogger(__name__)


class BurpJsonRpcClient:
    def __init__(self, connection: BurpSseConnection):
        self.connection = connection
        self._ids = itertools.count(1)

    def call(self, method: str, params: dict[str, Any]) -> BurpRpcResult:
        request_id = next(self._ids)
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        LOGGER.info(json.dumps({"event": "burp_rpc_request", "method": method, "id": request_id}))

        direct = self.connection.post_json(payload)
        if direct and isinstance(direct, dict) and "id" in direct and int(direct.get("id", request_id)) == request_id:
            response = direct
        else:
            response = self.connection.wait_for_response(request_id, timeout=self.connection.config.rpc_timeout_seconds)

        if "error" in response and response["error"]:
            err = response["error"] if isinstance(response["error"], dict) else {"message": str(response["error"])}
            return BurpRpcResult(request_id=request_id, ok=False, error=err)

        result = response.get("result")
        if not isinstance(result, dict):
            return BurpRpcResult(request_id=request_id, ok=False, error={"message": "Missing or invalid result object"})
        return BurpRpcResult(request_id=request_id, ok=True, result=result)

    def require_call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        result = self.call(method, params)
        if not result.ok or result.result is None:
            message = result.error.get("message", "JSON-RPC call failed") if result.error else "JSON-RPC call failed"
            raise BurpJsonRpcError(message)
        return result.result

    def tools_list(self) -> dict[str, Any]:
        return self.require_call("tools/list", {})

    def tools_call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.require_call("tools/call", {"name": name, "arguments": arguments})
