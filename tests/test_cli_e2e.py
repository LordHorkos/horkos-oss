#!/usr/bin/env python3
"""End-to-end server test: horkos-scan a lab target, then serve + fetch it.
Run: python3 test_cli_e2e.py."""
import http.client
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from horkos_sec.cli import scan_main
from horkos_sec.webapp import make_server
from horkos_sec.persistence import list_runs


class _Vuln(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_GET(self):
        body = (b'<a href="/next">n</a>' if self.path == "/" else b"<p>leaf</p>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sid=abc")
        self.send_header("Server", "nginx/1.25.3")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _lab():
    srv = HTTPServer(("127.0.0.1", 0), _Vuln)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_scan_then_serve_end_to_end():
    lab, port = _lab()
    work = tempfile.mkdtemp()
    runs_root = os.path.join(work, "runs")
    cfg_path = os.path.join(work, "lab.json")
    cfg = {
        "program": "labrat",
        "authorized": True,
        "scope_text": "In scope\nURL\t127.0.0.1",
        "allowed_schemes": ["http"],
        "seeds": [f"http://127.0.0.1:{port}/"],
        "rate": 1000.0, "max_requests": 50, "max_pages": 10,
        "out_dir": os.path.join(runs_root, "labrat"),
        "target_profile": {"scope": "focused", "tech_familiarity": "high", "platform": "vdp"},
    }
    # the config uses http + a loopback host, so allow fast rate + private
    import horkos_sec.run_config as rc
    # build_run_plan would reject rate>0.3 without allow_fast_rate; the CLI sets
    # rate from config, so cap it here to the ceiling for the test
    cfg["rate"] = 0.3
    open(cfg_path, "w").write(json.dumps(cfg))

    try:
        rc_code = scan_main(["--config", cfg_path, "--allow-private"])
        assert rc_code == 0

        # the run was persisted and is discoverable
        runs = list_runs(runs_root)
        assert any(r["program"] == "labrat" for r in runs)
        out = os.path.join(runs_root, "labrat")
        assert os.path.isfile(os.path.join(out, "run.json"))
        assert os.path.isfile(os.path.join(out, "dashboard.html"))
        data = json.load(open(os.path.join(out, "run.json")))
        titles = {f["title"] for f in data["findings"]}
        assert any("Cookie" in t for t in titles)          # detectors ran on the lab
        assert data["target_score"]["verdict"] in ("commit", "learn", "drop")

        # serve and fetch index + run page
        srv = make_server(runs_root, port=0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            wp = srv.server_address[1]
            c = http.client.HTTPConnection("127.0.0.1", wp, timeout=5)
            c.request("GET", "/"); idx = c.getresponse(); ib = idx.read(); c.close()
            assert idx.status == 200 and b"labrat" in ib
            c = http.client.HTTPConnection("127.0.0.1", wp, timeout=5)
            c.request("GET", "/run/labrat"); rp = c.getresponse(); rb = rp.read(); c.close()
            assert rp.status == 200 and b"KASABONKA" in rb
        finally:
            srv.shutdown()
    finally:
        lab.shutdown()


def _main():
    test_scan_then_serve_end_to_end()
    print("ok 1 test_scan_then_serve_end_to_end")
    print("RESULT: 1/1 passed")


if __name__ == "__main__":
    _main()
