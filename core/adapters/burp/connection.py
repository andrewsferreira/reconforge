"""Burp MCP SSE transport and session handling."""

from __future__ import annotations

import json
import logging
import queue
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Optional

from core.adapters.burp.config import BurpMcpConfig
from core.adapters.burp.exceptions import BurpMalformedEventError, BurpNotReachableError, BurpResponseTimeoutError
from core.adapters.burp.models import BurpSessionState, BurpSseEvent

LOGGER = logging.getLogger(__name__)


def parse_sse_stream_line(line: str, event_type: str, event_id: str, data_lines: list[str]) -> tuple[str, str, list[str], bool]:
    """Parse an SSE line and return updated parser state.

    Returns tuple (event_type, event_id, data_lines, event_complete).
    """
    if line == "":
        return event_type, event_id, data_lines, True
    if line.startswith(":"):
        return event_type, event_id, data_lines, False
    if line.startswith("event:"):
        return line.split(":", 1)[1].strip() or "message", event_id, data_lines, False
    if line.startswith("id:"):
        return event_type, line.split(":", 1)[1].strip(), data_lines, False
    if line.startswith("data:"):
        data_lines.append(line.split(":", 1)[1].lstrip())
    return event_type, event_id, data_lines, False


class BurpSseConnection:
    def __init__(self, config: BurpMcpConfig):
        self.config = config
        self.state = BurpSessionState(base_url=config.base_url)
        self._sse_response = None
        self._stop = threading.Event()
        self._events: "queue.Queue[BurpSseEvent]" = queue.Queue()
        self._reader_thread: Optional[threading.Thread] = None

    def connect(self) -> BurpSessionState:
        last_error: Optional[Exception] = None
        for attempt in range(self.config.max_retries + 1):
            try:
                self.state.retries_used = attempt
                self._open_sse()
                self.state.sse_connected = True
                self._discover_session_and_endpoint(timeout=self.config.rpc_timeout_seconds)
                self.state.transport_stable = True
                LOGGER.info(json.dumps({"event": "burp_sse_connected", "session_id": self.state.session_id or ""}))
                return self.state
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                self.state.sse_connected = False
                self.state.transport_stable = False
                LOGGER.warning(json.dumps({"event": "burp_sse_connect_retry", "attempt": attempt, "error": str(exc)}))
                self.close()
                time.sleep(0.2)

        raise BurpNotReachableError(str(last_error or "unable to connect to Burp MCP"))

    def _open_sse(self) -> None:
        url = urllib.parse.urljoin(self.config.base_url, self.config.sse_path)
        if not url.startswith(("http://", "https://")):
            raise BurpNotReachableError(f"Refusing non-http(s) Burp MCP base_url: {url!r}")
        req = urllib.request.Request(url, headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"}, method="GET")
        try:
            self._sse_response = urllib.request.urlopen(req, timeout=self.config.connect_timeout_seconds)  # nosec B310 - scheme checked above
        except urllib.error.URLError as exc:
            raise BurpNotReachableError(f"SSE connection failed: {exc}") from exc
        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader_thread.start()

    def _reader_loop(self) -> None:
        response = self._sse_response
        if response is None:
            return

        event_type = "message"
        event_id = ""
        data_lines: list[str] = []
        try:
            while not self._stop.is_set():
                raw = response.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
                if line.endswith("\r"):
                    line = line[:-1]
                event_type, event_id, data_lines, complete = parse_sse_stream_line(line, event_type, event_id, data_lines)
                if complete:
                    if data_lines:
                        self._events.put(BurpSseEvent(event=event_type, data="\n".join(data_lines), event_id=event_id))
                    event_type, event_id, data_lines = "message", "", []
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning(json.dumps({"event": "burp_sse_reader_error", "error": str(exc)}))

    def _discover_session_and_endpoint(self, timeout: float) -> None:
        deadline = time.time() + timeout
        fallback = urllib.parse.urljoin(self.config.base_url, self.config.message_path_fallback)
        self.state.message_endpoint = fallback

        while time.time() < deadline:
            try:
                event = self._events.get(timeout=0.2)
            except queue.Empty:
                continue
            self._consume_hint_event(event)
            if self.state.session_id and self.state.message_endpoint:
                return

        LOGGER.info(json.dumps({"event": "burp_sse_hint_timeout", "fallback": fallback}))

    def _consume_hint_event(self, event: BurpSseEvent) -> None:
        payload = event.data.strip()
        if not payload:
            return

        if event.event.lower() == "endpoint":
            self._consume_endpoint_hint(payload)
            return

        if not payload.startswith("{"):
            return
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise BurpMalformedEventError(f"Malformed SSE JSON payload: {payload[:200]}") from exc

        session_id = str(obj.get("sessionId", "") or obj.get("session_id", "")).strip()
        if session_id:
            self.state.session_id = session_id
        endpoint = str(obj.get("endpoint", "") or obj.get("messageEndpoint", "")).strip()
        if endpoint:
            self._consume_endpoint_hint(endpoint)

    def _consume_endpoint_hint(self, endpoint_hint: str) -> None:
        resolved = urllib.parse.urljoin(self.config.base_url, endpoint_hint)
        if not resolved.startswith(("http://", "https://")):
            # urljoin lets an absolute-scheme hint override the base URL's
            # scheme entirely (e.g. a "file:///etc/passwd" endpoint hint
            # would otherwise be adopted verbatim). The Burp MCP server is
            # config-trusted, not attacker-controlled, but a compromised or
            # spoofed server is exactly the threat this guards against —
            # keep the existing/fallback endpoint instead of adopting this one.
            LOGGER.warning(json.dumps({
                "event": "burp_sse_endpoint_hint_rejected",
                "reason": "non-http(s) scheme",
                "hint": endpoint_hint[:200],
            }))
            return
        self.state.message_endpoint = resolved

        parsed = urllib.parse.urlparse(resolved)
        query_params = urllib.parse.parse_qs(parsed.query)
        sid = (query_params.get("sessionId") or query_params.get("session_id") or [""])[0]
        if sid:
            self.state.session_id = sid
            return

        # Burp observed endpoint payload may contain query in non-standard text chunks.
        match = re.search(r"sessionId=([a-zA-Z0-9\\-]+)", endpoint_hint)
        if match:
            self.state.session_id = match.group(1)

    def post_json(self, payload: Dict) -> Dict:
        endpoint = self.state.message_endpoint
        if not endpoint:
            raise BurpNotReachableError("No message endpoint available for JSON-RPC")
        if not endpoint.startswith(("http://", "https://")):
            # Defense in depth: _consume_endpoint_hint already rejects
            # non-http(s) endpoints, but never urlopen an unexpected scheme
            # here either.
            raise BurpNotReachableError(f"Refusing non-http(s) message endpoint: {endpoint!r}")
        headers = {"Content-Type": "application/json"}
        if self.state.session_id:
            headers["x-session-id"] = self.state.session_id
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.config.rpc_timeout_seconds) as resp:  # nosec B310 - scheme checked above
                text = resp.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as exc:
            raise BurpNotReachableError(f"JSON-RPC POST failed: {exc}") from exc

        if not text.strip():
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Burp can acknowledge with a non-JSON body (e.g., "Accepted") and
            # deliver JSON-RPC result asynchronously over SSE.
            return {"_non_json_body": text.strip()}

    def wait_for_response(self, request_id: int, timeout: float) -> Dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                event = self._events.get(timeout=0.25)
            except queue.Empty:
                continue
            payload = event.data.strip()
            if not payload.startswith("{"):
                continue
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if int(obj.get("id", -1)) == int(request_id):
                return obj
        raise BurpResponseTimeoutError(f"Timeout waiting for JSON-RPC response id={request_id}")

    def close(self) -> None:
        self._stop.set()
        if self._sse_response is not None:
            try:
                self._sse_response.close()
            except Exception:  # noqa: BLE001  # nosec B110 - best-effort teardown of a possibly already-closed/broken socket; must never block shutdown
                pass
            self._sse_response = None
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=0.3)
