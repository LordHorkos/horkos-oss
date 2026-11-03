#!/usr/bin/env python3
"""Tests for har.py (Phase 7, option C). Run: python3 test_har.py."""
import json
import sys

from horkos_sec.har import parse_har, har_seeds
from horkos_sec.governance import Engagement
from horkos_sec.scope_guard import ScopeConfig
from horkos_sec.run_config import build_run_plan, RunOptions


def _har(entries):
    return json.dumps({"log": {"version": "1.2", "entries": entries}})


def _e(url, method="GET"):
    return {"request": {"method": method, "url": url}, "response": {"status": 200}}


def test_extracts_urls_and_params():
    har = _har([
        _e("https://example.com/"),
        _e("https://api.example.com/v1/users?page=1&q=x"),
        _e("https://example.com/", "GET"),               # dupe
    ])
    r = parse_har(har)
    assert r.urls == ["https://example.com/", "https://api.example.com/v1/users?page=1&q=x"]
    assert r.params == {"page", "q"}


def test_records_methods():
    r = parse_har(_har([_e("https://example.com/x", "POST"), _e("https://example.com/x", "GET")]))
    assert r.methods["https://example.com/x"] == {"POST", "GET"}


def test_drops_non_http_and_fragments():
    r = parse_har(_har([_e("data:text/html,x"), _e("https://example.com/p#frag")]))
    assert r.urls == ["https://example.com/p"]


def test_accepts_dict_and_bytes():
    doc = {"log": {"entries": [_e("https://example.com/a")]}}
    assert har_seeds(doc) == ["https://example.com/a"]
    assert har_seeds(json.dumps(doc).encode()) == ["https://example.com/a"]


def test_malformed_entries_skipped_not_fatal():
    r = parse_har(_har(["junk", {"no_request": 1}, _e("https://example.com/ok")]))
    assert r.urls == ["https://example.com/ok"]


def test_bad_har_raises():
    for bad in ["not json", "{}", json.dumps({"log": {}})]:
        try:
            parse_har(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_har_seeds_feed_run_plan_and_are_scope_filtered():
    # HAR endpoints become seeds; out-of-scope ones are rejected by build_run_plan
    seeds = har_seeds(_har([
        _e("https://example.com/app"),
        _e("https://api.example.com/v1/data"),
        _e("https://tracker.evil/collect"),
    ]))
    eng = Engagement("acme", ScopeConfig(allowed_domains=["example.com"],
                                         allowed_schemes=["https"]),
                     authorized=True, modes=("observe",))
    plan = build_run_plan(eng, seeds, RunOptions())
    assert "https://example.com/app" in plan.seeds
    assert "https://api.example.com/v1/data" in plan.seeds
    assert all("evil" not in s for s in plan.seeds)
    assert any("evil" in u for u, _ in plan.rejected)


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
