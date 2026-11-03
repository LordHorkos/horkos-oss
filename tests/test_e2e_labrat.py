#!/usr/bin/env python3
"""
End-to-end validation gate (#15).

Stands up a deliberately misconfigured loopback target (a "lab rat") and runs the
whole pipeline against it observe-only: authorize -> crawl -> passive detect ->
evidence -> audit -> report. Asserts the detectors fire the findings they should,
the audit chain verifies, evidence is reproducible, and out-of-scope links are
never fetched.

This is the proof that must pass before the detectors are pointed at any real
program. Run: python3 test_e2e_labrat.py  (also collected by pytest).
"""
import os
import sys
import tempfile
import threading
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer

from horkos_sec import (
    Engagement, build_run_plan, RunOptions, Controller,
    AuditLog, KillSwitch, EvidenceStore, build_report, ScopeConfig,
)


class _VulnApp(BaseHTTPRequestHandler):
    """Intentionally misconfigured: no security headers, flagless cookie, version leak."""
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/b":                       # local redirect
            self.send_response(302)
            self.send_header("Location", "/a")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sid=abc123")          # no Secure/HttpOnly/SameSite
        self.send_header("Server", "nginx/1.25.3")            # version disclosure
        self.send_header("X-Powered-By", "PHP/8.1.2")
        self.end_headers()
        if self.path == "/":
            self.wfile.write(
                b'<a href="/a">a</a><a href="/b">b</a>'
                b'<a href="https://evil.test/x">offsite</a>'
            )
        else:
            self.wfile.write(b"<p>leaf</p>")


def _serve():
    srv = HTTPServer(("127.0.0.1", 0), _VulnApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_end_to_end_labrat():
    srv, port = _serve()
    out = tempfile.mkdtemp()
    try:
        eng = Engagement(
            program="labrat",
            scope=ScopeConfig(allowed_exact=["127.0.0.1"], allowed_schemes=["http"]),
            authorized=True, modes=("observe",),
        )
        plan = build_run_plan(
            eng, [f"http://127.0.0.1:{port}/"],
            RunOptions(mode="observe", rate=1000.0, allow_fast_rate=True,
                       headers={"X-HackerOne-Research": "horkos"}, output_dir=out),
        )
        audit = AuditLog(os.path.join(out, "audit.jsonl"))
        store = EvidenceStore(out)
        res = Controller(plan, audit=audit, kill=KillSwitch(), evidence=store,
                         discover=True, max_pages=20, max_depth=3,
                         resolve_allow_private=True).run()

        # 1. crawl stayed in scope and followed local links
        fetched = {f.url for f in res.fetches}
        assert f"http://127.0.0.1:{port}/" in fetched
        assert f"http://127.0.0.1:{port}/a" in fetched
        assert not any("evil.test" in u for u in fetched), "offsite link must not be fetched"
        assert not res.aborted

        # 2. detectors fired the expected findings
        titles = {f.title for f in res.findings}
        assert "Missing Content-Security-Policy" in titles
        assert "Missing X-Content-Type-Options: nosniff" in titles
        assert "Missing clickjacking protection" in titles
        assert "Missing Referrer-Policy" in titles
        assert "Cookie without HttpOnly flag" in titles
        assert "Cookie without SameSite attribute" in titles
        assert any(t.startswith("Technology/version disclosure") for t in titles)
        # http target -> HSTS and cookie-Secure are correctly NOT flagged
        assert "Missing HSTS header" not in titles
        assert "Cookie without Secure flag" not in titles

        # 3. findings are deduped across the crawled pages
        keys = [f.key() for f in res.findings]
        assert len(keys) == len(set(keys))

        # 4. every finding has reproducible, verifiable evidence
        for f in res.findings:
            eid = f.evidence.get("evidence_id")
            assert eid and store.verify(eid)

        # 5. the audit chain verifies
        ok, bad = AuditLog.verify(os.path.join(out, "audit.jsonl"))
        assert ok, f"audit chain broke at {bad}"

        # 6. a report renders with the findings
        md = build_report(res, store=store)
        assert "# Security findings — labrat" in md
        assert "Missing Content-Security-Policy" in md
        assert "nginx/1.25.3" in md or "PHP/8.1.2" in md
    finally:
        srv.shutdown()


def _main():
    test_end_to_end_labrat()
    print("ok 1 test_end_to_end_labrat")
    print("RESULT: 1/1 passed")


if __name__ == "__main__":
    _main()
