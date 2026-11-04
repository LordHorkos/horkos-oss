#!/usr/bin/env python3
"""Standalone tests for scope_guard.py. Run: python3 test_scope_guard.py."""
import sys

from horkos_sec.scope_guard import ScopeConfig, check_scope


def _cfg(**kw):
    kw.setdefault("allowed_domains", ["example.com"])
    return ScopeConfig(**kw)


def test_allows_root_and_subdomain():
    c = _cfg()
    assert check_scope("https://example.com/a", c).in_scope
    assert check_scope("https://sub.example.com/a", c).in_scope


def test_rejects_unrelated_host():
    r = check_scope("https://evil.test/a", _cfg())
    assert not r.in_scope and "not in scope" in r.reason


def test_allowed_exact_admits_only_exact_host():
    c = ScopeConfig(allowed_domains=[], allowed_exact=["api.example.com"])
    assert check_scope("https://api.example.com/a", c).in_scope
    assert not check_scope("https://sub.api.example.com/a", c).in_scope
    assert not check_scope("https://example.com/a", c).in_scope


def test_mix_wildcard_subtree_and_exact_host():
    # *.example.com (subtree) alongside a specific host on another domain
    c = ScopeConfig(allowed_domains=["example.com"], allowed_exact=["app.other.test"])
    assert check_scope("https://x.example.com/a", c).in_scope      # subtree
    assert check_scope("https://app.other.test/a", c).in_scope     # exact
    assert not check_scope("https://api.other.test/a", c).in_scope  # not the exact host


def test_config_requires_some_allow():
    try:
        ScopeConfig(allowed_domains=[], allowed_exact=[])
    except ValueError:
        return
    raise AssertionError("empty allow lists must raise")


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


def test_rejects_embedded_credentials():
    # user:pass@host is refused regardless of host match or port policy
    r = check_scope("https://user:pass@example.com/a", _cfg())
    assert not r.in_scope and "credentials" in r.reason
    r2 = check_scope("https://user@example.com/a", _cfg())
    assert not r2.in_scope and "credentials" in r2.reason


def test_allowed_ports_opt_in_denies_nonstandard():
    c = _cfg(allowed_ports=[443])
    r = check_scope("https://example.com:8443/a", c)
    assert not r.in_scope and "Port 8443" in r.reason


def test_allowed_ports_admits_default_and_explicit():
    c = _cfg(allowed_ports=[443])
    assert check_scope("https://example.com/a", c).in_scope        # no port -> default 443
    assert check_scope("https://example.com:443/a", c).in_scope    # explicit 443


def test_no_port_policy_allows_any_port():
    # default (allowed_ports=None) keeps lab scanning on odd ports working
    assert check_scope("https://example.com:8443/a", _cfg()).in_scope


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
