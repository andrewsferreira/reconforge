"""Phase 16: lab/vulnerable_app.py is the first-party local validation
target README.md's "Local Validation Lab" section references. These tests
confirm each endpoint actually exhibits the weakness ReconForge's web/api
modules are meant to detect, and that the loopback-only guard works.
"""

import http.client
import threading
from http.server import ThreadingHTTPServer

import pytest

from lab.vulnerable_app import LabRequestHandler, _validate_loopback_host


@pytest.fixture
def lab_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabRequestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _get(port, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read()
    headers = dict(resp.getheaders())
    conn.close()
    return resp.status, headers, body


def _post(port, path, data: bytes):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", path, body=data,
                  headers={"Content-Length": str(len(data))})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, body


# ── Missing security headers ────────────────────────────────────────

def test_index_omits_all_security_headers(lab_server):
    status, headers, _ = _get(lab_server, "/")
    assert status == 200
    lower_headers = {k.lower() for k in headers}
    for missing in (
        "x-frame-options", "x-content-type-options", "content-security-policy",
        "strict-transport-security", "x-xss-protection",
    ):
        assert missing not in lower_headers


# ── Reflected parameter ──────────────────────────────────────────────

def test_search_reflects_query_param_unescaped(lab_server):
    status, _, body = _get(lab_server, "/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
    assert status == 200
    assert b"<script>alert(1)</script>" in body


def test_search_with_no_query_param_does_not_crash(lab_server):
    status, _, body = _get(lab_server, "/search")
    assert status == 200
    assert b"You searched for:" in body


# ── Predictable / enumerable paths ──────────────────────────────────

def test_admin_path_is_reachable(lab_server):
    status, _, body = _get(lab_server, "/admin")
    assert status == 200
    assert b"Admin Panel" in body


def test_robots_txt_lists_disallow_entries(lab_server):
    status, _, body = _get(lab_server, "/robots.txt")
    assert status == 200
    assert b"Disallow: /admin" in body
    assert b"Disallow: /backup" in body


def test_unknown_path_returns_404(lab_server):
    status, _, _ = _get(lab_server, "/does-not-exist")
    assert status == 404


# ── Fake login (never actually authenticates) ───────────────────────

def test_login_get_returns_form(lab_server):
    status, _, body = _get(lab_server, "/login")
    assert status == 200
    assert b"<form" in body


def test_login_post_always_reports_invalid_credentials(lab_server):
    status, body = _post(lab_server, "/login", b"username=admin&password=admin")
    assert status == 200
    assert b"Invalid credentials" in body


# ── API status endpoint ──────────────────────────────────────────────

def test_api_status_returns_json(lab_server):
    status, headers, body = _get(lab_server, "/api/status")
    assert status == 200
    assert headers.get("Content-Type", "").startswith("application/json")
    assert b'"status": "ok"' in body


# ── Loopback-only guard ───────────────────────────────────────────────

def test_validate_loopback_host_accepts_loopback_addresses():
    assert _validate_loopback_host("127.0.0.1") == "127.0.0.1"
    assert _validate_loopback_host("localhost") == "localhost"
    assert _validate_loopback_host("::1") == "::1"


def test_validate_loopback_host_rejects_non_loopback():
    with pytest.raises(SystemExit):
        _validate_loopback_host("0.0.0.0")
    with pytest.raises(SystemExit):
        _validate_loopback_host("10.0.0.5")
