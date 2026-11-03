"""
Passive detectors — judge what a normal GET returned. No injection, no mutation,
no extra requests: each detector reads a FetchResult (status, headers, body) and
emits Findings.

Covered:
  * security headers — HSTS (https only), CSP, X-Content-Type-Options,
    framing (X-Frame-Options or CSP frame-ancestors), Referrer-Policy
  * cookie flags — Secure (https), HttpOnly, SameSite
  * info disclosure — Server / X-Powered-By / version-ish headers

Severities are stated at their true level and capped into the model band by
make_finding; passive findings sit in info/low/medium by nature.

A detector takes a result-like object with `.url`/`.final_url`, `.status`,
`.headers` (a lower-cased name->value dict), and `.body`. For headers that can
legitimately repeat (Set-Cookie), pass the raw values via `set_cookies=` since a
flat dict keeps only the last; run_passive_detectors accepts that too.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .body_detectors import detect_body
from .findings import Finding, make_finding


def _url(result) -> str:
    return getattr(result, "final_url", None) or getattr(result, "url", "") or ""


def _is_https(url: str) -> bool:
    return url.lower().startswith("https://")


def detect_security_headers(result) -> List[Finding]:
    url = _url(result)
    h = {k.lower(): v for k, v in (getattr(result, "headers", {}) or {}).items()}
    out: List[Finding] = []

    if _is_https(url) and "strict-transport-security" not in h:
        out.append(make_finding("Missing HSTS header", "low", url,
                                 category="security-headers",
                                 detail="No Strict-Transport-Security on an HTTPS response."))

    csp = h.get("content-security-policy", "")
    if not csp:
        out.append(make_finding("Missing Content-Security-Policy", "low", url,
                                 category="security-headers"))

    if h.get("x-content-type-options", "").strip().lower() != "nosniff":
        out.append(make_finding("Missing X-Content-Type-Options: nosniff", "info", url,
                                 category="security-headers"))

    frame_ancestors = "frame-ancestors" in csp.lower()
    if "x-frame-options" not in h and not frame_ancestors:
        out.append(make_finding("Missing clickjacking protection", "low", url,
                                 category="security-headers",
                                 detail="Neither X-Frame-Options nor CSP frame-ancestors is set."))

    if "referrer-policy" not in h:
        out.append(make_finding("Missing Referrer-Policy", "info", url,
                                 category="security-headers"))

    return out


def detect_cookies(result, set_cookies: Optional[List[str]] = None) -> List[Finding]:
    url = _url(result)
    h = {k.lower(): v for k, v in (getattr(result, "headers", {}) or {}).items()}
    cookies = list(set_cookies) if set_cookies is not None else (
        [h["set-cookie"]] if "set-cookie" in h else []
    )
    out: List[Finding] = []
    https = _is_https(url)

    for raw in cookies:
        attrs = [p.strip().lower() for p in raw.split(";")]
        name = raw.split("=", 1)[0].strip()
        flags = set(a.split("=")[0] for a in attrs[1:])
        if https and "secure" not in flags:
            out.append(make_finding("Cookie without Secure flag", "low", url,
                                     category="cookie",
                                     detail=f"Cookie '{name}' set over HTTPS without Secure.",
                                     evidence={"cookie": name}))
        if "httponly" not in flags:
            out.append(make_finding("Cookie without HttpOnly flag", "low", url,
                                     category="cookie",
                                     detail=f"Cookie '{name}' is readable from JavaScript.",
                                     evidence={"cookie": name}))
        if "samesite" not in flags:
            out.append(make_finding("Cookie without SameSite attribute", "info", url,
                                     category="cookie",
                                     detail=f"Cookie '{name}' has no SameSite.",
                                     evidence={"cookie": name}))
    return out


_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version",
                       "x-aspnetmvc-version", "x-runtime", "x-generator")


def detect_info_disclosure(result) -> List[Finding]:
    url = _url(result)
    h = {k.lower(): v for k, v in (getattr(result, "headers", {}) or {}).items()}
    out: List[Finding] = []
    for name in _DISCLOSURE_HEADERS:
        val = h.get(name)
        if not val:
            continue
        # a bare product name ("nginx") is low-signal; a version digit is the tell
        has_version = any(c.isdigit() for c in val)
        out.append(make_finding(
            f"Technology/version disclosure via {name}",
            "info", url, category="info-disclosure",
            detail=f"{name}: {val}" if has_version else f"{name} header present: {val}",
            evidence={name: val},
        ))
    return out


_PASSIVE = (detect_security_headers, detect_cookies, detect_info_disclosure, detect_body)


def run_passive_detectors(result, set_cookies: Optional[List[str]] = None) -> List[Finding]:
    """Run every passive detector over one response, de-duplicated by key."""
    findings: List[Finding] = []
    for det in _PASSIVE:
        if det is detect_cookies:
            findings.extend(det(result, set_cookies=set_cookies))
        else:
            findings.extend(det(result))
    seen = set()
    unique = []
    for f in findings:
        if f.key() not in seen:
            seen.add(f.key())
            unique.append(f)
    return unique
