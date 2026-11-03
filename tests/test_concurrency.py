#!/usr/bin/env python3
"""Phase 5 tests: thread-safe guard cap, HostRateLimiter, concurrent controller.
Run: python3 test_concurrency.py."""
import sys
import threading
import time
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer

from horkos_sec.request_guard import RequestGuard
from horkos_sec.rate_limiter import HostRateLimiter
from horkos_sec.scope_guard import ScopeConfig, check_scope
from horkos_sec.safe_resolver import resolve
from horkos_sec.controller import Controller, _group_by_host
from horkos_sec.governance import Engagement
from horkos_sec.run_config import build_run_plan, RunOptions


# ---- thread-safe guard cap -------------------------------------------------

class _OkScope:
    in_scope = True
    reason = ""


class _OkResolved:
    is_valid = True
    denial_reason = ""
    ip = "93.184.216.34"


def test_guard_cap_strict_under_threads():
    guard = RequestGuard(scope_check=lambda u: _OkScope(),
                         resolve=lambda h: _OkResolved(), max_requests=100)
    allowed = []
    lock = threading.Lock()

    def worker():
        n = 0
        for _ in range(100):
            if guard.evaluate("https://example.com/x").allowed:
                n += 1
        with lock:
            allowed.append(n)

    ts = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert sum(allowed) == 100, f"cap breached: {sum(allowed)}"
    assert guard.request_count == 100


def test_guard_denied_does_not_consume():
    guard = RequestGuard(scope_check=lambda u: _OkScope(),
                         resolve=lambda h: type("R", (), {"is_valid": False,
                                                          "denial_reason": "x", "ip": ""})(),
                         max_requests=5)
    for _ in range(10):
        guard.evaluate("https://example.com/x")
    assert guard.request_count == 0


# ---- per-host rate limiter -------------------------------------------------

def test_host_rate_limiter_global_cap():
    hrl = HostRateLimiter(rate=1000.0, burst=10, global_max_requests=3)
    got = sum(hrl.acquire(h, max_wait=0.1) for h in ["a", "b", "c", "a", "b"])
    assert got == 3 and hrl.consumed == 3


def test_host_rate_limiter_per_host_buckets():
    # each host has its own burst, so two hosts get their own allotment
    hrl = HostRateLimiter(rate=0.001, burst=2, global_max_requests=100)
    a = sum(hrl.acquire("a", max_wait=0.0) for _ in range(5))
    b = sum(hrl.acquire("b", max_wait=0.0) for _ in range(5))
    assert a == 2 and b == 2        # per-host burst, independent


# ---- concurrent controller -------------------------------------------------

class _H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_GET(self):
        time.sleep(0.05)
        body = b"ok"
        self.send_response(200); self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain"); self.end_headers()
        self.wfile.write(body)


def _server():
    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_group_by_host():
    g = _group_by_host(["http://a/1", "http://a/2", "http://b/1"])
    assert len(g) == 2


def test_concurrent_run_respects_global_cap():
    srv, port = _server()
    try:
        # two hosts (127.0.0.1 and localhost) so concurrency kicks in
        eng = Engagement("lab", ScopeConfig(allowed_exact=["127.0.0.1", "localhost"],
                                            allowed_schemes=["http"]),
                         authorized=True, modes=("observe",))
        seeds = [f"http://127.0.0.1:{port}/a", f"http://127.0.0.1:{port}/b",
                 f"http://localhost:{port}/a", f"http://localhost:{port}/b"]
        plan = build_run_plan(eng, seeds,
                              RunOptions(rate=1000.0, allow_fast_rate=True, max_requests=3))
        res = Controller(plan, resolve_allow_private=True, workers=4).run()
        ok = [f for f in res.fetches if f.ok]
        assert len(ok) <= 3, f"global cap breached: {len(ok)} ok fetches"
    finally:
        srv.shutdown()


def test_concurrent_path_runs_without_error():
    # Exercises the workers>1 thread-pool path. Only 127.0.0.1 is guaranteed
    # reachable cross-platform (localhost may resolve to ::1 in CI), so we assert
    # the concurrent run completes cleanly and does real work, not an exact count.
    srv, port = _server()
    try:
        eng = Engagement("lab", ScopeConfig(allowed_exact=["127.0.0.1", "localhost"],
                                            allowed_schemes=["http"]),
                         authorized=True, modes=("observe",))
        seeds = [f"http://127.0.0.1:{port}/a", f"http://localhost:{port}/a"]
        plan = build_run_plan(eng, seeds, RunOptions(rate=1000.0, allow_fast_rate=True))
        res = Controller(plan, resolve_allow_private=True, workers=4).run()
        assert not res.aborted
        assert any(f.ok for f in res.fetches)       # at least the 127.0.0.1 worker succeeded
        assert len(res.fetches) >= 1
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
