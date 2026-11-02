#!/usr/bin/env python3
"""Standalone tests for scope_guard.py. Run: python3 test_scope_guard.py."""
import sys

from scope_guard import ScopeConfig, check_scope


def _cfg(**kw):
    kw.setdefault("allowed_domains", ["example.com"])
    return ScopeConfig(**kw)


def test_allows_root_and_subdomain():
    c = _cfg()
    assert check_scope("https://example.com/a", c).in_scope
    assert check_scope("https://sub.example.com/a", c).in_scope


def test_rejects_unrelated_host():
    r = check_scope("https://evil.test/a", _cfg())
    assert not r.in_scope and "not in allowed_domains" in r.reason


def test_scheme_must_be_allowed():
    r = check_scope("http://example.com/a", _cfg())        # default allows https only
    assert not r.in_scope and "Scheme" in r.reason
    assert check_scope("http://example.com/a",
                       _cfg(allowed_schemes=["http", "https"])).in_scope


def test_missing_scheme_or_host_denied():
    assert not check_scope("example.com/a", _cfg()).in_scope
    assert not check_scope("https:///a", _cfg()).in_scope


def test_exact_match_refuses_subdomains():
    c = _cfg(allowed_domains=["host.example.com"], exact_match=True)
    assert check_scope("https://host.example.com/a", c).in_scope
    assert not check_scope("https://other.host.example.com/a", c).in_scope


def test_disallowed_bare_root_is_exact_only():
    # bare disallowed root blocks only that exact host, not a sibling subtree
    c = _cfg(allowed_domains=["example.com"], disallowed_domains=["prod.example.com"])
    assert not check_scope("https://prod.example.com/a", c).in_scope      # blocked exactly
    assert check_scope("https://api.stg.example.com/a", c).in_scope       # sibling allowed


def test_disallowed_subtree_prefix_blocks_all():
    for entry in [".prod.example.com", "*.prod.example.com"]:
        c = _cfg(allowed_domains=["example.com"], disallowed_domains=[entry])
        assert not check_scope("https://prod.example.com/a", c).in_scope
        assert not check_scope("https://x.prod.example.com/a", c).in_scope


def test_disallowed_wins_over_allowed():
    c = _cfg(allowed_domains=["example.com"], disallowed_domains=["*.example.com"])
    assert not check_scope("https://sub.example.com/a", c).in_scope


def test_empty_allowed_domains_rejected_at_config():
    try:
        ScopeConfig(allowed_domains=[])
    except ValueError:
        return
    raise AssertionError("empty allowed_domains must raise")


def test_case_insensitive():
    assert check_scope("https://EXAMPLE.com/a", _cfg()).in_scope


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
