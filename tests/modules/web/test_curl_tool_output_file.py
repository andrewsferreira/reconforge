"""Phase 6-D: curl_tool.py must not let Runner.run() clobber curl's own -o output.

Regression test for a real bug: passing the same path to both curl's -o
flag and Runner.run()'s output_file= caused Runner to overwrite curl's
real response with an empty string (since -o redirects the body away
from stdout, Runner then writes that now-empty captured stdout back
over the file). Uses a real local HTTP server and a real curl subprocess
— this bug does not reproduce with mocks, since the corruption happens
inside Runner.run()'s interaction with actual subprocess stdout capture.
"""

import http.server
import threading

import pytest

from core.logger import ReconLogger
from core.runner import Runner
from modules.web.tools.curl_tool import CurlTool


class _HeaderServer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Test-Marker", "reconforge-phase6d")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("X-Test-Marker", "reconforge-phase6d")
        self.end_headers()

    def log_message(self, *args):
        pass  # silence test output


@pytest.fixture
def local_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _HeaderServer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=5)


def test_fetch_headers_writes_real_curl_output_not_empty(tmp_path, local_server):
    port = local_server.server_address[1]
    url = f"http://127.0.0.1:{port}/"

    logger = ReconLogger(name="test", log_dir=tmp_path / "logs", verbose=False)
    runner = Runner(logger=logger, timeout=10, target="127.0.0.1")
    curl = CurlTool(runner=runner, logger=logger, output_dir=tmp_path)

    result = curl.fetch_headers(url)

    assert result.success is True
    headers_path = curl.get_headers_path()
    assert headers_path.is_file()
    content = headers_path.read_text()
    assert content != ""
    assert "X-Test-Marker" in content
    assert "reconforge-phase6d" in content
