#!/usr/bin/env python3
"""Tests for report_html.py. Run: python3 test_report_html.py."""
import os
import sys
import tempfile

from horkos_sec.report_html import build_html_report, write_html_report
from horkos_sec.controller import RunResult, FetchRecord
from horkos_sec.run_config import build_run_plan, RunOptions
from horkos_sec.governance import Engagement, AuditLog
from horkos_sec.scope_guard import ScopeConfig
from horkos_sec.findings import make_finding


def _result(findings, fetches=2):
    eng = Engagement("acme", ScopeConfig(allowed_domains=["example.com"],
                                         allowed_schemes=["https"]),
                     authorized=True, modes=("observe",))
    plan = build_run_plan(eng, ["https://example.com/"], RunOptions())
    r = RunResult(plan=plan)
    r.fetches = [FetchRecord(f"https://example.com/{i}", True, 200) for i in range(fetches)]
    r.findings = findings
    return r


def test_self_contained_no_external_resources():
    html = build_html_report(_result([]))
    assert html.startswith("<!doctype html>")
    assert "http://" not in html and "https://cdn" not in html.lower()  # no external refs
    assert "<i>No findings.</i>" in html


def test_target_controlled_text_is_escaped():
    # a finding whose fields contain markup must not inject raw HTML/JS
    f = make_finding("<script>alert(1)</script>", "low",
                     "https://example.com/<img src=x onerror=alert(2)>",
                     category="x", detail="<b>evil</b>")
    html = build_html_report(_result([f]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "onerror=alert(2)" not in html or "&lt;img" in html  # url escaped
    # the only real <script> is our own sort helper
    assert html.count("<script>") == 1


def test_counts_and_severity_rows():
    fs = [make_finding("AlphaMed", "medium", "https://example.com/1", category="c"),
          make_finding("BetaLow", "low", "https://example.com/2", category="c"),
          make_finding("GammaInfo", "info", "https://example.com/3", category="c")]
    html = build_html_report(_result(fs))
    assert "<td>1</td><td>1</td><td>1</td><td><b>3</b></td>" in html
    # medium sorts first by default ordering
    assert html.index("AlphaMed") < html.index("BetaLow") < html.index("GammaInfo")


def test_cwe_cvss_rendered():
    f = make_finding("CORS allows any origin with credentials", "medium",
                     "https://example.com/x", category="cors")
    html = build_html_report(_result([f]))
    assert "CWE-942" in html and "7.5" in html


def test_audit_badge():
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    AuditLog(p).record("request", url="https://example.com/a")
    html = build_html_report(_result([]), audit_path=p)
    assert "audit verified" in html


def test_write_to_file():
    path = os.path.join(tempfile.mkdtemp(), "out", "dash.html")
    write_html_report(_result([make_finding("x", "low", "https://example.com/y", category="c")]), path)
    assert os.path.exists(path) and "<!doctype html>" in open(path).read()


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
