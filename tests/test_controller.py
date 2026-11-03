#!/usr/bin/env python3
"""Tests for controller.py using a loopback HTTP server. Run: python3 test_controller.py."""
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from horkos_sec.controller import Controller
from horkos_sec.governance import AuditLog, Engagement, KillSwitch
from horkos_sec.run_config import build_run_plan, RunOptions
from horkos_sec.scope_guard import ScopeConfig


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        # HTML with a missing-headers response and an in-scope link to crawl
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sid=abc")       # no flags -> cookie findings
        self.end_headers()
        if self.path == "/":
            self.wfile.write(b'<a href="/next">n</a>')
        else:
            self.wfile.write(b"leaf")


def _server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _plan(port, **opts):
    eng = Engagement("lab", ScopeConfig(allowed_exact=["127.0.0.1"], allowed_schemes=["http"]),
                     authorized=True, modes=("observe",))
    seeds = opts.pop("seeds", [f"http://127.0.0.1:{port}/a", f"http://127.0.0.1:{port}/b"])
    return build_run_plan(eng, seeds, RunOptions(rate=1000.0, allow_fast_rate=True, **opts))


def test_runs_seeds_observe_only():
    srv, port = _server()
    try:
        plan = _plan(port)
        res = Controller(plan, resolve_allow_private=True).run()
        assert not res.aborted
        assert len(res.fetches) == 2 and all(f.ok and f.status == 200 for f in res.fetches)
        assert all(f.ip == "127.0.0.1" for f in res.fetches)
    finally:
        srv.shutdown()


def test_audit_log_written_and_verifies():
    srv, port = _server()
    try:
        p = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        audit = AuditLog(p)
        Controller(_plan(port), audit=audit, resolve_allow_private=True).run()
        ok, bad = AuditLog.verify(p)
        assert ok, f"chain broke at {bad}"
        lines = open(p).read().splitlines()
        # run_start + (authorize + request)*2 + run_end = 6
        assert len(lines) == 6, len(lines)
        assert '"action":"run_start"' in lines[0]
        assert '"action":"run_end"' in lines[-1]
    finally:
        srv.shutdown()


def test_kill_switch_stops_before_fetch():
    srv, port = _server()
    try:
        kill = KillSwitch()
        kill.trip("operator halt")
        res = Controller(_plan(port), kill=kill, resolve_allow_private=True).run()
        assert res.aborted and "operator halt" in res.abort_reason
        assert res.fetches == []
    finally:
        srv.shutdown()


def test_request_cap_denies_second_seed():
    srv, port = _server()
    try:
        plan = _plan(port, max_requests=1)
        res = Controller(plan, resolve_allow_private=True).run()
        assert res.fetches[0].ok
        assert not res.fetches[1].ok and "Max requests" in res.fetches[1].reason
    finally:
        srv.shutdown()


def test_private_target_refused_without_allow_private():
    # resolve_allow_private defaults False -> 127.0.0.1 fails resolution in the guard
    srv, port = _server()
    try:
        res = Controller(_plan(port)).run()   # resolve_allow_private not set
        assert all(not f.ok for f in res.fetches)
        assert any("IP validation failed" in f.reason or "private" in f.reason.lower()
                   for f in res.fetches)
    finally:
        srv.shutdown()


def test_detectors_produce_findings():
    srv, port = _server()
    try:
        plan = _plan(port, seeds=[f"http://127.0.0.1:{port}/"])
        res = Controller(plan, resolve_allow_private=True).run()
        cats = {f.category for f in res.findings}
        assert "security-headers" in cats and "cookie" in cats
        # dedup: each (category,title,url) appears once
        keys = [f.key() for f in res.findings]
        assert len(keys) == len(set(keys))
    finally:
        srv.shutdown()


def test_detect_off_yields_no_findings():
    srv, port = _server()
    try:
        plan = _plan(port, seeds=[f"http://127.0.0.1:{port}/"])
        res = Controller(plan, resolve_allow_private=True, detect=False).run()
        assert res.findings == [] and res.fetches[0].ok
    finally:
        srv.shutdown()


def test_discover_crawls_and_detects_across_pages():
    srv, port = _server()
    try:
        plan = _plan(port, seeds=[f"http://127.0.0.1:{port}/"])
        res = Controller(plan, resolve_allow_private=True, discover=True,
                         max_pages=10, max_depth=2).run()
        fetched = {f.url for f in res.fetches}
        assert f"http://127.0.0.1:{port}/" in fetched
        assert f"http://127.0.0.1:{port}/next" in fetched   # crawled the in-scope link
        # findings deduped across both pages
        keys = [f.key() for f in res.findings]
        assert len(keys) == len(set(keys)) and res.findings
    finally:
        srv.shutdown()


def test_evidence_captured_and_findings_tagged():
    import tempfile
    from horkos_sec.evidence import EvidenceStore
    srv, port = _server()
    try:
        out = tempfile.mkdtemp()
        plan = _plan(port, seeds=[f"http://127.0.0.1:{port}/"])
        store = EvidenceStore(out)
        res = Controller(plan, resolve_allow_private=True, evidence=store).run()
        assert res.findings
        eid = res.findings[0].evidence.get("evidence_id")
        assert eid, "findings must carry an evidence id"
        assert store.verify(eid)                       # stored body matches hash
        meta = store.load(eid)
        assert meta["status"] == 200
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
