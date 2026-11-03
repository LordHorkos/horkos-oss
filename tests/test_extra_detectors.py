#!/usr/bin/env python3
"""Tests for extra_detectors.py (Phase 4). Run: python3 test_extra_detectors.py."""
import sys
from dataclasses import dataclass, field
from typing import Dict

from horkos_sec.extra_detectors import (
    detect_cors, detect_mixed_content, detect_directory_listing,
    detect_open_redirect_params, detect_cookie_prefixes, detect_weak_xfo,
)
from horkos_sec.detectors import run_passive_detectors


@dataclass
class R:
    url: str = "https://example.com/"
    final_url: str = "https://example.com/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""


def _t(fs):
    return {f.title for f in fs}


def test_cors_star_with_creds_medium():
    fs = detect_cors(R(headers={"access-control-allow-origin": "*",
                                "access-control-allow-credentials": "true"}))
    assert fs and fs[0].severity == "medium"


def test_cors_star_low():
    assert "CORS allows any origin (ACAO: *)" in _t(detect_cors(
        R(headers={"access-control-allow-origin": "*"})))


def test_cors_null():
    assert "CORS allows null origin" in _t(detect_cors(
        R(headers={"access-control-allow-origin": "null"})))


def test_cors_clean():
    assert detect_cors(R(headers={"access-control-allow-origin": "https://example.com"})) == []


def test_mixed_content_flagged_on_https():
    fs = detect_mixed_content(R(body=b'<img src="http://cdn.evil/x.js">'))
    assert "Mixed content: http resource on https page" in _t(fs)


def test_mixed_content_ignored_on_http():
    assert detect_mixed_content(R(url="http://example.com/", final_url="http://example.com/",
                                  body=b'<img src="http://x/y">')) == []


def test_directory_listing():
    assert "Directory listing enabled" in _t(detect_directory_listing(
        R(body=b"<html><title>Index of /files</title>")))


def test_open_redirect_param():
    fs = detect_open_redirect_params(R(url="https://example.com/go?next=/a&x=1",
                                       final_url="https://example.com/go?next=/a&x=1"))
    assert "Redirect-like parameter present (unverified)" in _t(fs)
    assert "next" in fs[0].evidence["params"]


def test_open_redirect_none():
    assert detect_open_redirect_params(R(url="https://example.com/p?id=1",
                                         final_url="https://example.com/p?id=1")) == []


def test_cookie_prefix_secure_violation():
    fs = detect_cookie_prefixes(R(), set_cookies=["__Secure-sid=x; HttpOnly"])
    assert "__Secure- cookie without Secure flag" in _t(fs)


def test_cookie_prefix_host_violation():
    fs = detect_cookie_prefixes(R(), set_cookies=["__Host-sid=x; Secure; Domain=example.com; Path=/"])
    assert "__Host- cookie violates prefix rules" in _t(fs)


def test_cookie_prefix_host_ok():
    assert detect_cookie_prefixes(R(), set_cookies=["__Host-sid=x; Secure; Path=/"]) == []


def test_weak_xfo():
    assert "Weak or invalid X-Frame-Options value" in _t(detect_weak_xfo(
        R(headers={"x-frame-options": "ALLOWALL"})))
    assert detect_weak_xfo(R(headers={"x-frame-options": "DENY"})) == []


def test_meta_csp_suppresses_missing_csp():
    body = b'<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
    fs = run_passive_detectors(R(url="http://example.com/", final_url="http://example.com/",
                                 headers={}, body=body))
    assert "Missing Content-Security-Policy" not in _t(fs)


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
