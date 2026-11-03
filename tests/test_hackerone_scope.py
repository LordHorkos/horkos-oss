#!/usr/bin/env python3
"""Standalone tests for hackerone_scope.py. Run: python3 test_hackerone_scope.py."""
import json
import sys

from horkos_sec.hackerone_scope import parse_hackerone_scope
from horkos_sec.scope_guard import check_scope


def test_json_api_envelope():
    doc = {"data": [
        {"attributes": {"asset_type": "WILDCARD", "asset_identifier": "*.example.com",
                        "eligible_for_submission": True}},
        {"attributes": {"asset_type": "URL", "asset_identifier": "https://api.example.com",
                        "eligible_for_submission": True}},
        {"attributes": {"asset_type": "URL", "asset_identifier": "legacy.example.com",
                        "eligible_for_submission": False}},
        {"attributes": {"asset_type": "OTHER", "asset_identifier": "com.example.app",
                        "eligible_for_submission": True}},
    ]}
    p = parse_hackerone_scope(json.dumps(doc))
    assert p.config.allowed_domains == ["example.com"]
    assert p.config.allowed_exact == ["api.example.com"]
    assert p.config.disallowed_domains == ["legacy.example.com"]
    assert any("com.example.app" in s for s in p.skipped)
    # behaviour through the guard
    assert check_scope("https://x.example.com/a", p.config).in_scope      # wildcard subtree
    assert check_scope("https://api.example.com/a", p.config).in_scope    # exact host
    # sub.api.example.com is in scope here via the *.example.com wildcard, which
    # is correct — the exact entry doesn't narrow what the wildcard already covers.
    assert check_scope("https://sub.api.example.com/a", p.config).in_scope
    assert not check_scope("https://legacy.example.com/a", p.config).in_scope   # out of scope


def test_bare_list_of_assets():
    doc = [
        {"asset_identifier": "*.example.com", "asset_type": "WILDCARD", "eligible_for_submission": True},
        {"asset_identifier": "10.0.0.0/8", "asset_type": "CIDR", "eligible_for_submission": True},
    ]
    p = parse_hackerone_scope(json.dumps(doc))
    assert p.config.allowed_domains == ["example.com"]
    assert any("CIDR" in s for s in p.skipped)


def test_plain_text_table():
    text = """
    *.example.com
    api.example.com
    legacy.example.com  (out of scope)
    -blocked.example.com
    # a comment
    """
    p = parse_hackerone_scope(text)
    assert "example.com" in p.config.allowed_domains
    assert "api.example.com" in p.config.allowed_exact
    # both out-of-scope forms captured as subtree-dot or bare
    assert ".legacy.example.com" in p.config.disallowed_domains or "legacy.example.com" in p.config.disallowed_domains
    assert not check_scope("https://blocked.example.com/x", p.config).in_scope


def test_out_of_scope_wildcard_becomes_subtree_block():
    doc = [{"asset_identifier": "*.internal.example.com", "asset_type": "WILDCARD",
            "eligible_for_submission": False},
           {"asset_identifier": "*.example.com", "asset_type": "WILDCARD",
            "eligible_for_submission": True}]
    p = parse_hackerone_scope(json.dumps(doc))
    assert check_scope("https://x.example.com/a", p.config).in_scope
    assert not check_scope("https://y.internal.example.com/a", p.config).in_scope


def test_scheme_override():
    p = parse_hackerone_scope('[{"asset_identifier":"*.example.com","asset_type":"WILDCARD","eligible_for_submission":true}]',
                              allowed_schemes=["http", "https"])
    assert check_scope("http://x.example.com/a", p.config).in_scope


def test_empty_input_raises():
    for bad in ["", "   ", "\n\n"]:
        try:
            parse_hackerone_scope(bad)
        except ValueError:
            continue
        raise AssertionError("empty input must raise")


def test_no_web_assets_raises():
    doc = [{"asset_identifier": "com.example.app", "asset_type": "GOOGLE_PLAY_APP_ID",
            "eligible_for_submission": True}]
    try:
        parse_hackerone_scope(json.dumps(doc))
    except ValueError:
        return
    raise AssertionError("a scope with no web assets must raise")


def test_scope_table_tab_separated():
    # the real HackerOne copy: asset-type column, host column, eligibility column
    t = ("URL\tapi.example.com\tEligible for bounty\n"
         "WILDCARD\t*.example.com\tEligible for bounty\n"
         "URL\tlegacy.example.com\tOut of scope")
    p = parse_hackerone_scope(t)
    assert p.config.allowed_exact == ["api.example.com"]
    assert p.config.allowed_domains == ["example.com"]
    assert "legacy.example.com" in p.config.disallowed_domains
    assert check_scope("https://api.example.com/x", p.config).in_scope
    assert not check_scope("https://legacy.example.com/x", p.config).in_scope


def test_scope_table_section_headers():
    t = ("In scope\n"
         "URL\tapi.example.com\n"
         "*.example.com\n"
         "Out of scope\n"
         "admin.example.com\n"
         "GOOGLE_PLAY_APP_ID\tcom.example.app")
    p = parse_hackerone_scope(t)
    assert "example.com" in p.config.allowed_domains
    assert "api.example.com" in p.config.allowed_exact
    assert "admin.example.com" in p.config.disallowed_domains
    assert any("com.example.app" in s for s in p.skipped)
    assert not check_scope("https://admin.example.com/x", p.config).in_scope


def test_scope_table_multispace_columns():
    p = parse_hackerone_scope("URL      api.example.com      eligible")
    assert p.config.allowed_exact == ["api.example.com"]


def test_malformed_json_falls_back_to_text():
    # looks like JSON (leading brace) but isn't — must not crash, parse as text
    p = parse_hackerone_scope("{api.example.com\n*.example.com")
    assert p.config.allowed_domains or p.config.allowed_exact


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
