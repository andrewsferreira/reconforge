import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mcp_validation.burp.models import ValidationConfig
from mcp_validation.burp.validator import BurpMcpValidator


class MockMcpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # noqa: A003
        return

    def do_GET(self):  # noqa: N802
        if self.path not in {"/", "/sse"}:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        # MCP SSE hints: endpoint + optional session information.
        self.wfile.write(b"event: endpoint\n")
        self.wfile.write(b"data: /rpc\n\n")
        self.wfile.write(b"event: message\n")
        self.wfile.write(b'data: {"sessionId":"sess-1"}\n\n')
        self.wfile.flush()

        # Keep stream alive briefly so client can continue lifecycle.
        time.sleep(1.0)

    def do_POST(self):  # noqa: N802
        if self.path not in {"/rpc", "/?sessionId=sess-1"}:
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        method = payload.get("method")
        request_id = payload.get("id")

        if method == "tools/list":
            body = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": [
                        {"name": "get_proxy_http_history", "description": "Get Burp proxy history"},
                        {"name": "burp.scan.start", "description": "Start active scan"},
                    ]
                },
            }
        elif method == "tools/call":
            params = payload.get("params", {})
            if params.get("name") == "get_proxy_http_history":
                body = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"records": [{"url": "https://example.com", "method": "GET", "statusCode": 200}]},
                }
            else:
                body = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32000, "message": "tool restricted"},
                }
        else:
            body = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "method not found"},
            }

        raw = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _start_server() -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockMcpHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://{host}:{port}"


def test_validator_success_with_mock_mcp_server(tmp_path):
    server, thread, base_url = _start_server()
    try:
        config = ValidationConfig(base_url=base_url, connect_timeout_seconds=2, rpc_timeout_seconds=2, max_retries=1)
        validator = BurpMcpValidator(config)
        report = validator.run()

        assert report.success is True
        assert report.tool_count == 2
        assert report.connection.sse_connected is True
        assert report.safe_execution.success is True
        assert report.recommendation == "READY for ReconForge integration"

        output = validator.save_report(report, tmp_path / "report.json")
        parsed = json.loads(output.read_text())
        assert parsed["tool_count"] == 2
    finally:
        server.shutdown()
        server.server_close()


def test_validator_not_ready_when_unreachable():
    config = ValidationConfig(base_url="http://127.0.0.1:1", connect_timeout_seconds=0.5, rpc_timeout_seconds=0.5, max_retries=0)
    validator = BurpMcpValidator(config)

    report = validator.run()

    assert report.success is False
    assert report.recommendation == "NOT READY"
    assert report.tool_count == 0
    assert report.errors
