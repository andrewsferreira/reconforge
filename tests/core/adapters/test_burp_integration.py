import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core.adapters.burp.config import BurpMcpConfig
from core.adapters.burp.connection import BurpSseConnection, parse_sse_stream_line
from core.adapters.burp.exceptions import BurpResponseTimeoutError, BurpUnsupportedCapabilityError
from core.adapters.burp.policy import BurpCapabilityPolicy
from core.adapters.burp.provider import BurpMcpProvider


class MockBurpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # noqa: A003
        return

    def do_GET(self):  # noqa: N802
        if self.path != "/sse":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(b"event: endpoint\n")
        self.wfile.write(b"data: /rpc\n\n")
        self.wfile.write(b"event: message\n")
        self.wfile.write(b'data: {"sessionId":"sess-core"}\n\n')
        self.wfile.flush()
        time.sleep(1.0)

    def do_POST(self):  # noqa: N802
        if self.path != "/rpc":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        request_id = payload.get("id")
        method = payload.get("method")

        if method == "tools/list":
            body = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": [
                        {"name": "get_proxy_http_history", "description": "Read proxy history"},
                        {"name": "send_http1_request", "description": "Send HTTP/1 request"},
                        {"name": "set_proxy_intercept", "description": "Toggle intercept"},
                    ]
                },
            }
        elif method == "tools/call":
            tool = payload.get("params", {}).get("name")
            if tool == "get_proxy_http_history":
                body = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "records": [
                            {
                                "url": "https://example.com/api",
                                "method": "GET",
                                "statusCode": 200,
                                "responseBodyLength": 42,
                                "host": "example.com",
                            }
                        ]
                    },
                }
            elif tool == "send_http1_request":
                body = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "url": "https://example.com/submit",
                        "method": "POST",
                        "statusCode": 201,
                        "responseBodyLength": 12,
                        "host": "example.com",
                    },
                }
            else:
                body = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32001, "message": "blocked"}}
        else:
            body = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "not found"}}

        raw = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockBurpHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"


def test_sse_line_parser_extracts_event_fields():
    event, event_id, data_lines, complete = parse_sse_stream_line("event: endpoint", "message", "", [])
    assert event == "endpoint"
    assert complete is False

    event, event_id, data_lines, complete = parse_sse_stream_line("id: abc", event, event_id, data_lines)
    assert event_id == "abc"

    event, event_id, data_lines, complete = parse_sse_stream_line("data: /rpc", event, event_id, data_lines)
    assert data_lines == ["/rpc"]

    event, event_id, data_lines, complete = parse_sse_stream_line("", event, event_id, data_lines)
    assert complete is True


def test_wait_for_response_timeout_raises():
    conn = BurpSseConnection(BurpMcpConfig(base_url="http://127.0.0.1:1", rpc_timeout_seconds=0.1, max_retries=0))
    with pytest.raises(BurpResponseTimeoutError):
        conn.wait_for_response(request_id=99, timeout=0.05)


def test_policy_gating_and_safe_provider_surface():
    policy = BurpCapabilityPolicy()
    assert policy.is_allowed("get_proxy_http_history") is True
    assert policy.is_allowed("set_proxy_intercept") is False


def test_provider_discovery_and_safe_calls():
    server, base_url = _start_server()
    try:
        provider = BurpMcpProvider(
            config=BurpMcpConfig(base_url=base_url, sse_path="/sse", message_path_fallback="/rpc", rpc_timeout_seconds=2, connect_timeout_seconds=2)
        )
        state = provider.start()

        assert "get_proxy_http_history" in state.enabled_tools
        assert "send_http1_request" in state.enabled_tools
        assert "set_proxy_intercept" in state.disabled_tools

        records = provider.get_proxy_http_history({})
        assert records
        assert records[0].host == "example.com"
        assert records[0].status_code == 200

        sent = provider.send_http1_request({})
        assert sent[0].method == "POST"
        assert sent[0].status_code == 201

        with pytest.raises(BurpUnsupportedCapabilityError):
            provider._execute_and_normalize("set_proxy_intercept", {})
    finally:
        provider.stop()
        server.shutdown()
        server.server_close()


class ObservedBurpBehaviorHandler(BaseHTTPRequestHandler):
    """Simulates observed Burp transport:
    - GET / => SSE with endpoint event containing ?sessionId=...
    - POST /?sessionId=... => immediate non-JSON \"Accepted\"
    - JSON-RPC response delivered asynchronously over SSE
    """

    protocol_version = "HTTP/1.1"
    sse_response_queue: list[str] = []

    def log_message(self, format, *args):  # noqa: A003
        return

    def do_GET(self):  # noqa: N802
        if self.path != "/":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(b"event: endpoint\n")
        self.wfile.write(b"data: /?sessionId=sess-observed\n\n")
        self.wfile.flush()

        for _ in range(200):
            if self.sse_response_queue:
                msg = self.sse_response_queue.pop(0)
                self.wfile.write(b"event: message\n")
                self.wfile.write(f"data: {msg}\n\n".encode("utf-8"))
                self.wfile.flush()
            time.sleep(0.01)

    def do_POST(self):  # noqa: N802
        if not self.path.startswith("/?sessionId=sess-observed"):
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        rid = payload.get("id", 1)
        method = payload.get("method")

        if method == "tools/list":
            async_result = {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "tools": [
                        {"name": "get_proxy_http_history", "description": "Read history"},
                        {"name": "send_http1_request", "description": "Send request"},
                    ]
                },
            }
        else:
            async_result = {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {"records": [{"url": "https://example.org", "method": "GET", "statusCode": 200}]},
            }
        self.sse_response_queue.append(json.dumps(async_result))

        raw = b"Accepted"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def test_observed_burp_accepted_then_async_sse_response():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ObservedBurpBehaviorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    provider = BurpMcpProvider(config=BurpMcpConfig(base_url=base_url, sse_path="/", message_path_fallback="/"))
    try:
        state = provider.start()
        assert state.session.session_id == "sess-observed"
        assert state.session.message_endpoint.endswith("/?sessionId=sess-observed")

        history = provider.get_proxy_http_history({})
        assert history
        assert history[0].host == "example.org"
    finally:
        provider.stop()
        server.shutdown()
        server.server_close()
