#!/usr/bin/env python3
"""Tests for persistence.py + webapp.py. Run: python3 test_webapp.py."""
import http.client
import os
import sys
import tempfile
import threading

from horkos_sec.persistence import (
    save_run, load_run, list_runs, render_run_html, build_index_html, run_to_dict,
)
from horkos_sec.webapp import make_server
from horkos_sec.controller import RunResult, FetchRecord
from horkos_sec.run_config import build_run_plan, RunOptions
from horkos_sec.governance import Engagement
from horkos_sec.scope_guard import ScopeConfig
from horkos_sec.findings import make_finding
from horkos_sec.kasabonka import KASABONKA, TargetProfile


def _result(program="acme"):
    eng = Engagement(program, ScopeConfig(allowed_domains=["example.com"],
                                          allowed_exact=["api.example.com"],
                                          allowed_schemes=["https"]),
                     authorized=True, modes=("observe",))
    plan = build_run_plan(eng, ["https://example.com/"], RunOptions())
    r = RunResult(plan=plan)
    r.fetches = [FetchRecord(f"https://example.com/{i}", True, 200) for i in range(5)]
    r.findings = [make_finding("Missing HSTS header", "low", "https://example.com/",
                               category="security-headers"),
                  make_finding("CORS allows any origin (ACAO: *)", "low",
                               "https://api.example.com/x", category="cors")]
    return r


def _score():
    return KASABONKA().score(TargetProfile(program="acme", scope="focused",
                                           tech_familiarity="high", platform="vdp"))


# ---- persistence -----------------------------------------------------------

def test_save_load_roundtrip():
    d = tempfile.mkdtemp()
    save_run(_result(), d, _score())
    data = load_run(d)
    assert data["program"] == "acme" and data["pages"] == 5
    assert len(data["findings"]) == 2
    assert data["target_score"]["verdict"] in ("commit", "learn", "drop")


def test_render_run_html_from_dict():
    data = run_to_dict(_result(), _score())
    html = render_run_html(data)
    assert "KASABONKA — target assessment" in html
    assert "Missing HSTS header" in html
    assert "<!doctype html>" in html


def test_list_runs_sorted_and_counted():
    root = tempfile.mkdtemp()
    save_run(_result("alpha"), os.path.join(root, "alpha"), _score())
    save_run(_result("beta"), os.path.join(root, "beta"))
    runs = list_runs(root)
    assert {r["program"] for r in runs} == {"alpha", "beta"}
    a = next(r for r in runs if r["program"] == "alpha")
    assert a["counts"]["low"] == 2 and a["verdict"] in ("commit", "learn", "drop")


def test_index_html_lists_runs():
    html = build_index_html(list_runs(_make_root()))
    assert "acme" in html and "/run/" in html


def _make_root():
    root = tempfile.mkdtemp()
    save_run(_result(), os.path.join(root, "acme"), _score())
    return root


# ---- webapp ----------------------------------------------------------------

def _serve():
    root = _make_root()
    srv = make_server(root, port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], root


def _get(port, path):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, body


def test_index_route():
    srv, port, _ = _serve()
    try:
        code, body = _get(port, "/")
        assert code == 200 and b"horkos-oss" in body and b"/run/acme" in body
    finally:
        srv.shutdown()


def test_run_route_renders_dashboard():
    srv, port, _ = _serve()
    try:
        code, body = _get(port, "/run/acme")
        assert code == 200
        assert b"KASABONKA" in body and b"Missing HSTS header" in body
    finally:
        srv.shutdown()


def test_unknown_run_404():
    srv, port, _ = _serve()
    try:
        assert _get(port, "/run/nope")[0] == 404
    finally:
        srv.shutdown()


def test_path_traversal_blocked():
    srv, port, _ = _serve()
    try:
        # invalid ids are rejected (404), never traverse out of the runs root
        for p in ["/run/..", "/run/%2e%2e", "/evidence/acme/..%2f..%2frun", "/../etc/passwd"]:
            assert _get(port, p)[0] in (400, 404)
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
