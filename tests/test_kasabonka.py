#!/usr/bin/env python3
"""Tests for kasabonka.py + merged dashboard. Run: python3 test_kasabonka.py."""
import sys

from horkos_sec.kasabonka import KASABONKA, TargetProfile
from horkos_sec.report_html import build_html_report
from horkos_sec.controller import RunResult, FetchRecord
from horkos_sec.run_config import build_run_plan, RunOptions
from horkos_sec.governance import Engagement
from horkos_sec.scope_guard import ScopeConfig
from horkos_sec.findings import make_finding


K = KASABONKA()


def test_strong_target_commits():
    p = TargetProfile(program="acme", scope="focused",
                      features=["roles", "payments", "uploads"],
                      tech_familiarity="high", tech_stack=["rest"],
                      hall_of_fame=20, program_age_months=3, last_resolved_days=90,
                      platform="vdp")
    s = K.score(p)
    assert s.total >= 25 and s.verdict == "commit"
    assert s.factors["scope_size"][0] == 5
    assert s.factors["platform_type"][0] == 5


def test_weak_target_drops():
    p = TargetProfile(program="meh", scope="wildcard", features=[],
                      tech_familiarity="low", tech_stack=["blockchain"],
                      hall_of_fame=500, program_age_months=40, last_resolved_days=2,
                      platform="public")
    s = K.score(p)
    assert s.total < 18 and s.verdict == "drop"
    assert any("drop" in r.lower() for r in s.recommendations)


def test_middle_learns():
    p = TargetProfile(program="mid", scope="moderate", features=["api"],
                      tech_familiarity="medium", program_age_months=12,
                      hall_of_fame=120, platform="private")
    s = K.score(p)
    assert 18 <= s.total < 25 and s.verdict == "learn"


def test_hard_tech_penalizes_familiarity():
    base = K.score(TargetProfile(tech_familiarity="high", tech_stack=["rest"]))
    hard = K.score(TargetProfile(tech_familiarity="high", tech_stack=["iot"]))
    assert hard.factors["tech_familiarity"][0] < base.factors["tech_familiarity"][0]


def test_unknown_density_is_neutral():
    s = K.score(TargetProfile())
    assert s.factors["hunter_density"][0] == 3


def test_signals_from_run_suggests_features():
    eng = Engagement("acme", ScopeConfig(allowed_domains=["example.com"],
                                         allowed_schemes=["https"]),
                     authorized=True, modes=("observe",))
    plan = build_run_plan(eng, ["https://example.com/"], RunOptions())
    r = RunResult(plan=plan)
    r.fetches = [FetchRecord("https://example.com/x", True, 200)]
    r.findings = [make_finding("x", "low", "https://example.com/admin/upload", category="cookie")]
    sig = K.signals_from_run(r)
    assert "uploads" in sig["suggested_features"] and "admin" in sig["suggested_features"]
    assert sig["suggested_scope"] == "focused"


def test_principles_present():
    assert len(KASABONKA.principles) >= 5


# ---- merged dashboard ------------------------------------------------------

def _result():
    eng = Engagement("acme", ScopeConfig(allowed_domains=["example.com"],
                                         allowed_schemes=["https"]),
                     authorized=True, modes=("observe",))
    plan = build_run_plan(eng, ["https://example.com/"], RunOptions())
    r = RunResult(plan=plan)
    r.findings = [make_finding("Missing HSTS header", "low", "https://example.com/",
                               category="security-headers")]
    return r


def test_dashboard_merges_scorecard_and_findings():
    s = K.score(TargetProfile(program="acme", scope="focused", tech_familiarity="high"))
    html = build_html_report(_result(), target_score=s)
    assert "KASABONKA — target assessment" in html
    assert "Findings" in html
    assert "Missing HSTS header" in html
    assert f"{s.total}/30" in html


def test_dashboard_without_scorecard_still_works():
    html = build_html_report(_result())
    assert "KASABONKA" not in html
    assert "Missing HSTS header" in html


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
