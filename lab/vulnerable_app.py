#!/usr/bin/env python3
"""ReconForge Local Validation Lab — intentionally-weak HTTP target.

Serves a handful of deliberately weak endpoints so the `web`/`api` modules
have something real to find when following README.md's "Local Validation
Lab" smoke-test instructions. Pure standard library, no third-party
dependencies, no external downloads — the whole target is this one file.

This is NOT a general-purpose vulnerable-app framework (no SQLi, no real
auth, no file upload). It exists solely to give ReconForge's passive/
low-risk checks (missing security headers, reflected-parameter echoing,
predictable paths, robots.txt disallow entries) something to detect
locally and repeatably. Never bind this to anything but loopback.

Usage::

    python3 lab/vulnerable_app.py [--port 8008] [--host 127.0.0.1]

Endpoints:

- ``GET /``            index page, links to the others, no security headers set
- ``GET /search?q=``   reflects ``q`` unescaped into the response body
- ``GET /admin``       predictable/enumerable stub page
- ``GET|POST /login``  fake login form; POST always returns "invalid credentials"
- ``GET /api/status``  small JSON blob for the ``api`` module to fingerprint
- ``GET /robots.txt``  lists a couple of Disallow entries as enumeration bait
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class LabRequestHandler(BaseHTTPRequestHandler):
    server_version = "ReconForgeLab/1.0"

    # Deliberately quiet — this is a local test fixture, not a real server.
    def log_message(self, fmt: str, *args) -> None:  # noqa: A002
        pass

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Deliberately NOT setting X-Frame-Options / X-Content-Type-Options /
        # Content-Security-Policy / Strict-Transport-Security /
        # X-XSS-Protection — this is the weakness surface_discovery.py's
        # SECURITY_HEADERS check is meant to catch.
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (stdlib method name)
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            self._send(200, self._index_page())
        elif path == "/search":
            self._send(200, self._search_page(query))
        elif path == "/admin":
            self._send(200, b"<html><body><h1>Admin Panel (stub)</h1></body></html>")
        elif path == "/login":
            self._send(200, self._login_form())
        elif path == "/api/status":
            self._send(200, json.dumps({"status": "ok", "service": "reconforge-lab"}).encode(), "application/json")
        elif path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin\nDisallow: /backup\n", "text/plain")
        else:
            self._send(404, b"<html><body><h1>404 Not Found</h1></body></html>")

    def do_POST(self) -> None:  # noqa: N802
        if urlsplit(self.path).path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)  # discard — never actually authenticates
            self._send(200, b"<html><body>Invalid credentials.</body></html>")
        else:
            self._send(404, b"<html><body><h1>404 Not Found</h1></body></html>")

    @staticmethod
    def _index_page() -> bytes:
        return (
            b"<html><body><h1>ReconForge Local Validation Lab</h1>"
            b'<ul><li><a href="/search?q=test">search</a></li>'
            b'<li><a href="/admin">admin</a></li>'
            b'<li><a href="/login">login</a></li>'
            b'<li><a href="/api/status">api/status</a></li></ul>'
            b"</body></html>"
        )

    @staticmethod
    def _search_page(query: dict) -> bytes:
        q = query.get("q", [""])[0]
        # Intentionally reflects the raw query param unescaped — this is
        # the one deliberately-unsafe line in the whole file, and it's
        # the point: it gives ReconForge's reflected-parameter heuristics
        # something real to detect against a target that can never be
        # anything but localhost.
        unsafe_reflection = f"<p>You searched for: {q}</p>".encode()
        safe_wrapper_open = b"<html><body><h1>Search</h1>"
        safe_wrapper_close = (
            b'<p><small>escaped for reference: '
            + html.escape(q).encode()
            + b"</small></p></body></html>"
        )
        return safe_wrapper_open + unsafe_reflection + safe_wrapper_close

    @staticmethod
    def _login_form() -> bytes:
        return (
            b"<html><body><h1>Login</h1>"
            b'<form method="POST" action="/login">'
            b'<input name="username"><input name="password" type="password">'
            b'<button type="submit">Log in</button></form></body></html>'
        )


def _validate_loopback_host(host: str) -> str:
    if host not in _LOOPBACK_HOSTS:
        raise SystemExit(
            f"Refusing to bind to {host!r} — this target is intentionally weak "
            f"(missing security headers, unescaped reflection) and must never "
            f"be reachable from anywhere but loopback. Use one of: "
            f"{', '.join(sorted(_LOOPBACK_HOSTS))}"
        )
    return host


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8008)
    parser.add_argument("--host", type=_validate_loopback_host, default="127.0.0.1")
    args = parser.parse_args(argv)

    server = ThreadingHTTPServer((args.host, args.port), LabRequestHandler)
    print(f"ReconForge local validation lab listening on http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
