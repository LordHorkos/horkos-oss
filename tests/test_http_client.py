#!/usr/bin/env python3
"""Tests for http_client.py using a real loopback HTTP server.
Run: python3 test_http_client.py."""
import sys
import threading
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer

from horkos_sec.http_client import GuardedHTTPClient
from horkos_sec.request_guard import RequestGuard
from horkos_sec.rate_limiter import TokenBucket
from horkos_sec.safe_resolver import resolve
from horkos_sec.scope_guard import ScopeConfig, check_scope


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _emit(self):
        path = self.path
        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://offsite.example/evil")
            self.end_headers()
            return
        if path == "/redir-local":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("X-Test", "yes")
        self.end_headers()
        self.wfile.write(b"hello-body")

    def do_GET(self):
        self._emit()

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()


def _server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _client(port, **kw):
    # scope admits the loopback host; resolver allows private so 127.0.0.1 validates
    scope = ScopeConfig(allowed_exact=["localhost", "127.0.0.1"],
                        allowed_schemes=["http"])
    guard = RequestGuard(
        scope_check=partial(check_scope, scope=scope),
        resolve=partial(resolve, allow_private=True),
        max_requests=kw.pop("max_requests", 100),
    )
    bucket = kw.pop("bucket", None)
    return GuardedHTTPClient(guard, bucket=bucket,
                             headers={"X-Research": "horkos"}, timeout=5.0, **kw)


def test_basic_get_records_response():
    srv, port = _server()
    try:
        r = _client(port).fetch(f"http://127.0.0.1:{port}/ok")
        assert r.ok and r.status == 200, r.reason
        assert r.body == b"hello-body"
        assert r.headers.get("x-test") == "yes"
        assert r.ip == "127.0.0.1"
    finally:
        srv.shutdown()


def test_out_of_scope_is_refused_before_send():
    # no server needed; guard refuses first
    r = _client(0).fetch("http://evil.test/x")
    assert not r.ok and "Scope violation" in r.reason
    assert r.status is None


def test_mutating_method_refused():
    r = _client(0).fetch("http://127.0.0.1:1/x", method="POST")
    assert not r.ok and "Method" in r.reason


def test_redirect_offsite_is_reguarded_and_blocked():
    srv, port = _server()
    try:
        r = _client(port).fetch(f"http://127.0.0.1:{port}/redirect")
        assert not r.ok, "redirect to offsite host must be refused"
        assert "Scope violation" in r.reason
        assert r.redirects == [f"http://127.0.0.1:{port}/redirect"]
    finally:
        srv.shutdown()


def test_local_redirect_followed():
    srv, port = _server()
    try:
        r = _client(port).fetch(f"http://127.0.0.1:{port}/redir-local")
        assert r.ok and r.status == 200 and r.body == b"hello-body"
        assert r.final_url.endswith("/ok")
    finally:
        srv.shutdown()


def test_request_budget_exhaustion():
    srv, port = _server()
    try:
        c = _client(port, max_requests=1)
        assert c.fetch(f"http://127.0.0.1:{port}/ok").ok
        r = c.fetch(f"http://127.0.0.1:{port}/ok")
        assert not r.ok and "Max requests" in r.reason
    finally:
        srv.shutdown()


def test_rate_limiter_budget_blocks():
    srv, port = _server()
    try:
        bucket = TokenBucket(rate=1000.0, burst=1, max_requests=1)
        c = _client(port, bucket=bucket)
        assert c.fetch(f"http://127.0.0.1:{port}/ok").ok      # consumes the one token-cap
        r = c.fetch(f"http://127.0.0.1:{port}/ok")
        assert not r.ok and "rate limit" in r.reason
    finally:
        srv.shutdown()


def test_body_truncation():
    srv, port = _server()
    try:
        c = _client(port)
        c._max_body = 4
        r = c.fetch(f"http://127.0.0.1:{port}/ok")
        assert r.ok and r.body == b"hell" and r.truncated
    finally:
        srv.shutdown()


def _main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    n = 0
    for t in tests:
        t(); n += 1; print(f"ok {n} {t.__name__}")
    print(f"RESULT: {n}/{len(tests)} passed")
    sys.exit(0 if n == len(tests) else 1)


if __name__ == "__main__":
    _main()
