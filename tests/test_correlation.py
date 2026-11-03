#!/usr/bin/env python3
"""Standalone tests for correlation.py. Run: python3 test_correlation.py.

Locks the Phase-A triage behavior: raw findings fold into ranked unique issues,
confidence gates slop below an emit floor without dropping it, and cross-run
stability lifts recurring issues. Also round-trips the serialized form used by
run.json / the dashboard.
"""
import sys

from horkos_sec.correlation import (
    correlate, family, Issue, Correlation, DEFAULT_EMIT_FLOOR, prior_issue_keys,
)
from horkos_sec.findings import make_finding


def _hdr(url):
    # low-signal, high-volume header hygiene — the slop we want suppressed
    return make_finding("Missing Content-Security-Policy", "info", url,
                        category="security-headers")


def test_folds_repeats_across_urls_into_one_issue():
    # same header missing on 12 pages -> ONE issue with count 12
    findings = [_hdr(f"https://example.com/p{i}") for i in range(12)]
    corr = correlate(findings)
    assert corr.raw_count == 12
    assert corr.unique_count == 1
    only = (corr.issues + corr.suppressed)[0]
    assert only.count == 12
    assert len(only.urls) == 12


def test_header_noise_is_suppressed_not_dropped():
    findings = [_hdr(f"https://example.com/p{i}") for i in range(12)]
    corr = correlate(findings)
    assert corr.issues == []                      # nothing surfaced
    assert len(corr.suppressed) == 1              # but kept
    assert corr.suppressed[0].confidence < DEFAULT_EMIT_FLOOR


def test_high_signal_finding_is_surfaced():
    f = make_finding("CORS allows any origin with credentials", "high",
                     "https://example.com/api", category="cors")
    corr = correlate([f])
    assert len(corr.issues) == 1
    iss = corr.issues[0]
    assert iss.true_severity == "high"
    assert iss.confidence >= DEFAULT_EMIT_FLOOR
    assert iss.cwe == "CWE-942"


def test_true_severity_from_chain_marker_drives_confidence():
    # a finding capped from critical must score on its TRUE severity, not the cap
    f = make_finding("Serious thing", "critical", "https://example.com/x",
                     detail="leaked", category="c")
    corr = correlate([f])
    iss = (corr.issues + corr.suppressed)[0]
    assert iss.severity == "medium"               # display cap
    assert iss.true_severity == "critical"        # real level preserved
    assert iss.confidence >= DEFAULT_EMIT_FLOOR    # surfaced because critical


def test_mixed_run_slops_down_and_signal_up():
    findings = [_hdr(f"https://example.com/p{i}") for i in range(10)]
    findings.append(make_finding("Private key exposed (RSA)", "high",
                                 "https://example.com/backup.txt", category="secret"))
    corr = correlate(findings)
    assert len(corr.issues) == 1                   # only the secret surfaces
    assert corr.issues[0].title == "Private key exposed"   # family-collapsed
    assert any(i.title == "Missing Content-Security-Policy" for i in corr.suppressed)


def test_family_collapses_variable_suffixes():
    assert family("Private key exposed (RSA)") == "Private key exposed"
    assert family("Technology/version disclosure: nginx/1.25") == "Technology/version disclosure"
    assert family("Directory listing enabled") == "Directory listing enabled"


def test_ranked_by_confidence_desc():
    a = make_finding("CORS allows any origin with credentials", "high",
                     "https://example.com/a", category="cors")          # high conf
    b = make_finding("Directory listing enabled", "medium",
                     "https://example.com/b", category="dirlist")       # mid conf
    corr = correlate([b, a])
    assert [i.title for i in corr.issues][0] == "CORS allows any origin with credentials"
    confs = [i.confidence for i in corr.issues]
    assert confs == sorted(confs, reverse=True)


def test_cross_run_stability_lifts_and_flags():
    f = make_finding("Directory listing enabled", "medium",
                     "https://example.com/d", category="dirlist")
    key = ("dirlist", "Directory listing enabled")
    base_corr = correlate([f])
    base = (base_corr.issues + base_corr.suppressed)[0]
    # seen in 3 prior runs -> stable flag + higher confidence than the no-prior case
    stable = correlate([f], prior=[{key}, {key}, {key}])
    iss = (stable.issues + stable.suppressed)[0]
    assert iss.stable is True
    assert iss.prior_seen == 3
    assert iss.confidence >= base.confidence


def test_new_issue_flagged_against_known_surface():
    f = make_finding("CORS allows any origin with credentials", "high",
                     "https://example.com/a", category="cors")
    # prior runs exist but never had this issue -> it's new
    corr = correlate([f], prior=[{("security-headers", "Missing Content-Security-Policy")}])
    iss = corr.issues[0]
    assert iss.is_new is True
    assert iss.prior_seen == 0


def test_emit_floor_is_configurable():
    f = _hdr("https://example.com/p")
    # drop the floor to 0 and the header issue surfaces
    corr = correlate([f], emit_floor=0.0)
    assert len(corr.issues) == 1 and corr.suppressed == []


def test_empty_is_safe():
    corr = correlate([])
    assert corr.raw_count == 0 and corr.unique_count == 0
    assert "0 observations" in corr.summary()


def test_correlation_round_trips_through_dict():
    findings = [
        make_finding("CORS allows any origin with credentials", "high",
                     "https://example.com/a", category="cors"),
        _hdr("https://example.com/p0"), _hdr("https://example.com/p1"),
    ]
    corr = correlate(findings)
    d = corr.to_dict()
    back = Correlation.from_dict(d)
    assert [i.title for i in back.issues] == [i.title for i in corr.issues]
    assert [i.confidence for i in back.issues] == [i.confidence for i in corr.issues]
    assert [i.count for i in back.suppressed] == [i.count for i in corr.suppressed]
    assert d["surfaced_count"] == len(corr.issues)


def test_prior_issue_keys_reads_saved_runs():
    import tempfile, os
    from horkos_sec.controller import RunResult, FetchRecord
    from horkos_sec.run_config import build_run_plan, RunOptions
    from horkos_sec.governance import Engagement
    from horkos_sec.scope_guard import ScopeConfig
    from horkos_sec.persistence import save_run

    root = tempfile.mkdtemp()
    eng = Engagement("acme", ScopeConfig(allowed_domains=["example.com"],
                                         allowed_schemes=["https"]),
                     authorized=True, modes=("observe",))
    plan = build_run_plan(eng, ["https://example.com/"], RunOptions())
    r = RunResult(plan=plan)
    r.fetches = [FetchRecord("https://example.com/", True, 200)]
    r.findings = [make_finding("Directory listing enabled", "medium",
                               "https://example.com/d", category="dirlist")]
    save_run(r, os.path.join(root, "acme-1"), correlation=correlate(r.findings))

    prior = prior_issue_keys(root, "acme", exclude_id="acme-2")
    assert len(prior) == 1
    assert ("dirlist", "Directory listing enabled") in prior[0]
    # a different program sees no prior history
    assert prior_issue_keys(root, "other") == []


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
