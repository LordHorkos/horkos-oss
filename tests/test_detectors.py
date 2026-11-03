#!/usr/bin/env python3
"""Standalone tests for findings.py + detectors.py. Run: python3 test_detectors.py."""
import sys
from dataclasses import dataclass, field
from typing import Dict

from horkos_sec.findings import make_finding, Finding
from horkos_sec.detectors import (
    detect_security_headers, detect_cookies, detect_info_disclosure,
    run_passive_detectors,
)


@dataclass
class R:
    url: str = "https://example.com/"
    final_url: str = ""
    status: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""


def _titles(findings):
    return {f.title for f in findings}


# ---- findings --------------------------------------------------------------

def test_make_finding_caps_severity():
    f = make_finding("x", "critical", "https://e/", detail="d", category="c")
    assert f.severity == "medium"                      # capped
    assert f.detail.startswith("CHAIN_SEVERITY=critical")
    g = make_finding("y", "low", "https://e/")
    assert g.severity == "low" and "CHAIN_SEVERITY" not in g.detail


def test_finding_key_dedups_same_url_title():
    a = make_finding("t", "low", "https://e/a", category="c")
    b = make_finding("t", "low", "https://e/a", category="c")
    assert a.key() == b.key()


# ---- security headers ------------------------------------------------------

def test_all_headers_missing_flagged():
    t = _titles(detect_security_headers(R()))
    assert "Missing HSTS header" in t
    assert "Missing Content-Security-Policy" in t
    assert "Missing X-Content-Type-Options: nosniff" in t
    assert "Missing clickjacking protection" in t
    assert "Missing Referrer-Policy" in t


def test_well_configured_headers_clean():
    r = R(headers={
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    })
    assert detect_security_headers(r) == []            # CSP frame-ancestors covers framing


def test_hsts_not_flagged_on_http():
    r = R(url="http://example.com/", headers={})
    assert "Missing HSTS header" not in _titles(detect_security_headers(r))


def test_xfo_satisfies_framing():
    r = R(headers={"x-frame-options": "DENY"})
    assert "Missing clickjacking protection" not in _titles(detect_security_headers(r))


# ---- cookies ---------------------------------------------------------------

def test_cookie_missing_all_flags():
    r = R()
    t = _titles(detect_cookies(r, set_cookies=["sid=abc"]))
    assert t == {"Cookie without Secure flag", "Cookie without HttpOnly flag",
                 "Cookie without SameSite attribute"}


def test_cookie_fully_flagged_clean():
    r = R()
    out = detect_cookies(r, set_cookies=["sid=abc; Secure; HttpOnly; SameSite=Lax"])
    assert out == []


def test_cookie_secure_not_required_on_http():
    r = R(url="http://example.com/")
    t = _titles(detect_cookies(r, set_cookies=["sid=abc; HttpOnly; SameSite=Lax"]))
    assert "Cookie without Secure flag" not in t


def test_cookie_from_header_dict_fallback():
    r = R(headers={"set-cookie": "sid=abc"})
    assert len(detect_cookies(r)) == 3


# ---- info disclosure -------------------------------------------------------

def test_version_disclosure_flagged():
    r = R(headers={"server": "nginx/1.25.3", "x-powered-by": "PHP/8.1.2"})
    t = _titles(detect_info_disclosure(r))
    assert any("server" in x for x in t) and any("x-powered-by" in x for x in t)


def test_no_disclosure_headers_clean():
    assert detect_info_disclosure(R(headers={"server": ""})) == []


# ---- aggregate -------------------------------------------------------------

def test_run_passive_dedups_and_aggregates():
    r = R(headers={"set-cookie": "sid=abc", "server": "Apache/2.4.58"})
    out = run_passive_detectors(r)
    keys = [f.key() for f in out]
    assert len(keys) == len(set(keys))                 # no dupes
    cats = {f.category for f in out}
    assert {"security-headers", "cookie", "info-disclosure"} <= cats
    assert all(f.severity in ("info", "low", "medium") for f in out)


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
