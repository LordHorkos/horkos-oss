#!/usr/bin/env python3
"""Phase 1 transport tests: connection reuse + DNS cache. Run: python3 test_transport.py."""
import sys
import threading
import time
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer

from horkos_sec.http_client import GuardedHTTPClient
from horkos_sec.request_guard import RequestGuard
from horkos_sec.safe_resolver import resolve, ResolutionCache, _check_ip
from horkos_sec.scope_guard import ScopeConfig, check_scope

_CONNECTIONS = []


class _KAHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"          # enables keep-alive

    def setup(self):
        _CONNECTIONS.append(1)             # one per TCP connection accepted
        super().setup()

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _server(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _client(**kw):
    scope = ScopeConfig(allowed_exact=["127.0.0.1"], allowed_schemes=["http"])
    guard = RequestGuard(scope_check=partial(check_scope, scope=scope),
                         resolve=partial(resolve, allow_private=True),
                         max_requests=100)
    return GuardedHTTPClient(guard, timeout=5.0, **kw)


def test_connection_reused_across_requests():
    _CONNECTIONS.clear()
    srv, port = _server(_KAHandler)
    try:
        c = _client()
        for _ in range(4):
            assert c.fetch(f"http://127.0.0.1:{port}/").ok
        c.close()
        assert len(_CONNECTIONS) == 1, f"expected 1 TCP connection, got {len(_CONNECTIONS)}"
    finally:
        srv.shutdown()


def test_reuse_disabled_opens_each_time():
    _CONNECTIONS.clear()
    srv, port = _server(_KAHandler)
    try:
        c = _client(reuse_connections=False)
        for _ in range(3):
            assert c.fetch(f"http://127.0.0.1:{port}/").ok
        c.close()
        assert len(_CONNECTIONS) == 3
    finally:
        srv.shutdown()


class _CloseHandler(_KAHandler):
    protocol_version = "HTTP/1.0"          # server closes after each response


def test_server_closing_connection_still_works():
    _CONNECTIONS.clear()
    srv, port = _server(_CloseHandler)
    try:
        c = _client()
        for _ in range(3):
            r = c.fetch(f"http://127.0.0.1:{port}/")
            assert r.ok and r.body == b"ok"
        c.close()
    finally:
        srv.shutdown()


# ---- DNS cache -------------------------------------------------------------

def test_cache_skips_second_lookup_but_revalidates():
    cache = ResolutionCache(ttl=60)
    r1 = resolve("127.0.0.1", allow_private=True, cache=cache)
    assert r1.is_valid and cache.get("127.0.0.1") == ["127.0.0.1"]
    # cached, but validation still runs: without allow_private the same cached
    # address is now refused -> cache cannot bypass SSRF checks
    r2 = resolve("127.0.0.1", allow_private=False, cache=cache)
    assert not r2.is_valid and ("blocked network" in r2.denial_reason
                                or "loopback" in r2.denial_reason.lower())


def test_cache_ttl_expiry():
    cache = ResolutionCache(ttl=0.05)
    resolve("127.0.0.1", allow_private=True, cache=cache)
    assert cache.get("127.0.0.1") is not None
    time.sleep(0.1)
    assert cache.get("127.0.0.1") is None


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
