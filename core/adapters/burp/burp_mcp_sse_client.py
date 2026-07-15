#!/usr/bin/env python3
"""
Burp MCP SSE client

What it does:
- Connects to Burp MCP SSE endpoint
- Extracts sessionId from the 'endpoint' event
- Keeps the SSE stream open in a background thread
- Sends JSON-RPC requests via HTTP POST
- Waits for responses that arrive asynchronously over SSE
- Supports tools/list as an initial validation call

Tested logic is based on the observed Burp behavior:
1. GET / -> SSE stream with endpoint event containing ?sessionId=...
2. POST /?sessionId=... -> returns "Accepted"
3. Actual JSON-RPC response arrives later on the SSE stream

Requirements:
    pip install requests

Usage:
    python3 burp_mcp_sse_client.py

Optional:
    BURP_MCP_BASE_URL=http://127.0.0.1:9876 python3 burp_mcp_sse_client.py
"""

from __future__ import annotations

import json
import os
import queue
import re
import threading
from dataclasses import dataclass, field
from typing import Any

import requests

DEFAULT_BASE_URL = os.getenv("BURP_MCP_BASE_URL", "http://127.0.0.1:9876")
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_READ_TIMEOUT = 60
DEFAULT_RPC_TIMEOUT = 20


class MCPError(Exception):
    """Base MCP client error."""


class MCPConnectionError(MCPError):
    """Connection-related error."""


class MCPTimeoutError(MCPError):
    """Timeout waiting for SSE or RPC response."""


class MCPProtocolError(MCPError):
    """Unexpected or malformed MCP/SSE payload."""


@dataclass
class SSEEvent:
    event: str = "message"
    data: str = ""
    raw_lines: list[str] = field(default_factory=list)


class BurpMCPClient:
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: int = DEFAULT_READ_TIMEOUT,
        rpc_timeout: int = DEFAULT_RPC_TIMEOUT,
        debug: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.rpc_timeout = rpc_timeout
        self.debug = debug

        self._session = requests.Session()
        self._stop_event = threading.Event()
        self._sse_thread: threading.Thread | None = None

        self.session_id: str | None = None
        self._sse_ready = threading.Event()

        # JSON-RPC responses correlated by id
        self._pending: dict[int, queue.Queue[dict[str, Any]]] = {}
        self._pending_lock = threading.Lock()

    def log(self, message: str) -> None:
        if self.debug:
            print(f"[BurpMCP] {message}")

    def start(self) -> None:
        """Start SSE listener and wait until sessionId is received."""
        if self._sse_thread and self._sse_thread.is_alive():
            self.log("SSE listener already running.")
            return

        self.log(f"Connecting to SSE endpoint at {self.base_url}")
        self._stop_event.clear()
        self._sse_thread = threading.Thread(target=self._run_sse_listener, daemon=True)
        self._sse_thread.start()

        ready = self._sse_ready.wait(timeout=self.connect_timeout)
        if not ready or not self.session_id:
            raise MCPConnectionError(
                "Failed to initialize SSE session or extract sessionId from Burp MCP."
            )

        self.log(f"SSE session established. sessionId={self.session_id}")

    def stop(self) -> None:
        """Stop the client and background SSE listener."""
        self.log("Stopping client.")
        self._stop_event.set()
        if self._sse_thread and self._sse_thread.is_alive():
            self._sse_thread.join(timeout=2)

        self._session.close()

    def _run_sse_listener(self) -> None:
        headers = {"Accept": "text/event-stream"}

        try:
            with self._session.get(
                self.base_url,
                headers=headers,
                stream=True,
                timeout=(self.connect_timeout, self.read_timeout),
            ) as response:
                response.raise_for_status()

                content_type = response.headers.get("Content-Type", "")
                self.log(f"SSE connected. Content-Type={content_type}")

                if "text/event-stream" not in content_type:
                    raise MCPProtocolError(
                        f"Expected text/event-stream, got {content_type!r}"
                    )

                current_event = SSEEvent()

                for raw_line in response.iter_lines(decode_unicode=True):
                    if self._stop_event.is_set():
                        self.log("Stop requested. Exiting SSE loop.")
                        return

                    if raw_line is None:
                        continue

                    line = raw_line.rstrip("\r")
                    current_event.raw_lines.append(line)

                    # Blank line = dispatch event
                    if line == "":
                        self._handle_sse_event(current_event)
                        current_event = SSEEvent()
                        continue

                    if line.startswith(":"):
                        # Comment/heartbeat
                        continue

                    if line.startswith("event:"):
                        current_event.event = line.split(":", 1)[1].strip()
                    elif line.startswith("data:"):
                        chunk = line.split(":", 1)[1].lstrip()
                        if current_event.data:
                            current_event.data += "\n" + chunk
                        else:
                            current_event.data = chunk

                self.log("SSE stream ended unexpectedly.")

        except Exception as exc:
            self.log(f"SSE listener failed: {exc!r}")

    def _handle_sse_event(self, event: SSEEvent) -> None:
        if not event.raw_lines:
            return

        if event.event == "endpoint":
            self.log(f"Received endpoint event: {event.data}")
            if self.session_id is None:
                match = re.search(r"sessionId=([a-zA-Z0-9\-]+)", event.data)
                if not match:
                    raise MCPProtocolError(
                        f"Could not extract sessionId from endpoint event: {event.data!r}"
                    )
                self.session_id = match.group(1)
                self._sse_ready.set()
            return

        if not event.data:
            self.log(f"Ignoring SSE event without data. event={event.event}")
            return

        self.log(f"Received SSE event={event.event} data={event.data[:300]}")

        # Try to parse data as JSON-RPC payload
        try:
            payload = json.loads(event.data)
        except json.JSONDecodeError:
            self.log("SSE data was not JSON; ignoring.")
            return

        if not isinstance(payload, dict):
            self.log("SSE JSON payload was not an object; ignoring.")
            return

        rpc_id = payload.get("id")
        if rpc_id is None:
            self.log("SSE JSON payload has no id; ignoring.")
            return

        if not isinstance(rpc_id, int):
            self.log(f"SSE JSON payload id is not int: {rpc_id!r}; ignoring.")
            return

        with self._pending_lock:
            response_queue = self._pending.get(rpc_id)

        if response_queue is None:
            self.log(f"No pending request found for id={rpc_id}; ignoring.")
            return

        response_queue.put(payload)

    def _post_jsonrpc(self, payload: dict[str, Any]) -> str:
        if not self.session_id:
            raise MCPConnectionError("No sessionId available. Did you call start()?")

        post_url = f"{self.base_url}?sessionId={self.session_id}"
        headers = {"Content-Type": "application/json"}

        self.log(f"POST JSON-RPC to {post_url}: {json.dumps(payload)}")
        response = self._session.post(
            post_url,
            headers=headers,
            json=payload,
            timeout=(self.connect_timeout, self.read_timeout),
        )
        response.raise_for_status()
        body = response.text.strip()

        self.log(f"POST response status={response.status_code} body={body!r}")
        return body

    def request(self, method: str, params: dict[str, Any] | None = None, rpc_id: int = 1) -> dict[str, Any]:
        """
        Send a JSON-RPC request and wait for the asynchronous SSE response.

        Returns the full JSON-RPC response object.
        """
        if params is None:
            params = {}

        response_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)

        with self._pending_lock:
            if rpc_id in self._pending:
                raise MCPError(f"RPC id {rpc_id} is already pending.")
            self._pending[rpc_id] = response_queue

        payload = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": method,
            "params": params,
        }

        try:
            post_body = self._post_jsonrpc(payload)

            # Burp observed behavior: immediate body is "Accepted"
            # Do not require immediate JSON here.
            if post_body and post_body not in {"Accepted", '"Accepted"'}:
                self.log(f"Unexpected immediate POST body: {post_body!r}")

            try:
                response = response_queue.get(timeout=self.rpc_timeout)
            except queue.Empty as exc:
                raise MCPTimeoutError(
                    f"Timed out waiting for SSE response for method={method!r}, id={rpc_id}"
                ) from exc

            return response

        finally:
            with self._pending_lock:
                self._pending.pop(rpc_id, None)

    def tools_list(self) -> dict[str, Any]:
        return self.request("tools/list", params={}, rpc_id=1)

    def tools_call(self, name: str, arguments: dict[str, Any] | None = None, rpc_id: int = 2) -> dict[str, Any]:
        if arguments is None:
            arguments = {}

        return self.request(
            "tools/call",
            params={
                "name": name,
                "arguments": arguments,
            },
            rpc_id=rpc_id,
        )


def print_tools_list(response: dict[str, Any]) -> None:
    print("\n=== tools/list response ===")
    print(json.dumps(response, indent=2, ensure_ascii=False))

    result = response.get("result", {})
    tools = result.get("tools", [])

    if not isinstance(tools, list):
        print("\nNo valid tools list found in response.")
        return

    print(f"\nDiscovered {len(tools)} tool(s):")
    for idx, tool in enumerate(tools, start=1):
        if not isinstance(tool, dict):
            print(f"  {idx}. <invalid tool entry>")
            continue

        name = tool.get("name", "<no name>")
        description = tool.get("description", "")
        print(f"  {idx}. {name}")
        if description:
            print(f"     {description}")


def main() -> int:
    client = BurpMCPClient(debug=True)

    try:
        client.start()

        response = client.tools_list()
        print_tools_list(response)

        print("\nStatus: READY_FOR_NEXT_STEP")
        return 0

    except Exception as exc:
        print("\nStatus: FAILED")
        print(f"Error: {exc!r}")
        return 1

    finally:
        client.stop()


if __name__ == "__main__":
    raise SystemExit(main())
