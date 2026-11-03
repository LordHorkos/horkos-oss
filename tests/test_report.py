#!/usr/bin/env python3
"""Standalone tests for report.py. Run: python3 test_report.py."""
import os
import sys
import tempfile

from horkos_sec.report import build_report, write_report
from horkos_sec.controller import RunResult, FetchRecord
from horkos_sec.run_config import build_run_plan, RunOptions
from horkos_sec.governance import Engagement
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


def test_empty_report_has_no_findings_note():
    md = build_report(_result([]))
    assert "# Security findings — acme" in md
    assert "_No findings._" in md
    assert "| **total** | **0** |" in md


def test_findings_sorted_by_severity():
    findings = [
        make_finding("Info thing", "info", "https://example.com/a", category="x"),
        make_finding("Med thing", "medium", "https://example.com/b", category="y"),
        make_finding("Low thing", "low", "https://example.com/c", category="z"),
    ]
    md = build_report(_result(findings))
    i_med = md.index("Med thing")
    i_low = md.index("Low thing")
    i_info = md.index("Info thing")
    assert i_med < i_low < i_info                    # medium, then low, then info


def test_remediation_and_url_present():
    f = make_finding("Missing HSTS header", "low", "https://example.com/x",
                     category="security-headers")
    md = build_report(_result([f]))
    assert "https://example.com/x" in md
    assert "Strict-Transport-Security" in md         # remediation text


def test_capped_severity_shows_reported_level():
    f = make_finding("Serious thing", "critical", "https://example.com/x",
                     detail="bad", category="c")
    md = build_report(_result([f]))
    assert "reported critical" in md                 # true severity surfaced
    assert "medium" in md                            # stored (capped) severity


def test_evidence_reference_rendered():
    f = make_finding("Missing Referrer-Policy", "info", "https://example.com/x",
                     category="security-headers")
    f.evidence["evidence_id"] = "deadbeefcafe0001"
    md = build_report(_result([f]))
    assert "deadbeefcafe0001" in md


def test_summary_counts():
    findings = [
        make_finding("a", "low", "https://example.com/1", category="c"),
        make_finding("b", "low", "https://example.com/2", category="c"),
        make_finding("c", "info", "https://example.com/3", category="c"),
    ]
    md = build_report(_result(findings))
    assert "| low | 2 |" in md
    assert "| info | 1 |" in md
    assert "| **total** | **3** |" in md


def test_write_report_to_file():
    path = os.path.join(tempfile.mkdtemp(), "out", "report.md")
    f = make_finding("Missing HSTS header", "low", "https://example.com/x",
                     category="security-headers")
    write_report(_result([f]), path)
    assert os.path.exists(path)
    assert "Missing HSTS header" in open(path).read()


def test_aborted_note():
    r = _result([])
    r.aborted = True
    r.abort_reason = "operator halt"
    md = build_report(r)
    assert "aborted" in md and "operator halt" in md


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
