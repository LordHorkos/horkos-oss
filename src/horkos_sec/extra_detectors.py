"""
Additional passive detectors (Phase 4). All observe-only — they read the
response and the request URL, never send crafted input.

  * CORS misconfiguration (ACAO: * / null, * with credentials)
  * mixed content (http resources on an https page)
  * directory listing pages
  * redirect-like query parameters (flagged unverified — confirming an open
    redirect is active testing and is out of scope here)
  * cookie prefix rules (__Secure- / __Host-)
  * weak/invalid X-Frame-Options value
"""

from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urlsplit, parse_qsl

from .findings import Finding, make_finding


def _url(result) -> str:
    return getattr(result, "final_url", None) or getattr(result, "url", "") or ""


def _headers(result) -> dict:
    return {k.lower(): v for k, v in (getattr(result, "headers", {}) or {}).items()}


def _text(result) -> str:
    b = getattr(result, "body", b"") or b""
    return b[: 1 << 20].decode("utf-8", "replace") if isinstance(b, bytes) else b[: 1 << 20]


def detect_cors(result) -> List[Finding]:
    url, h = _url(result), _headers(result)
    acao = (h.get("access-control-allow-origin") or "").strip()
    acac = (h.get("access-control-allow-credentials") or "").strip().lower()
    out: List[Finding] = []
    if acao == "*" and acac == "true":
        out.append(make_finding("CORS allows any origin with credentials", "medium", url,
                                category="cors",
                                detail="Access-Control-Allow-Origin: * together with "
                                       "Allow-Credentials: true."))
    elif acao == "*":
        out.append(make_finding("CORS allows any origin (ACAO: *)", "low", url, category="cors"))
    elif acao.lower() == "null":
        out.append(make_finding("CORS allows null origin", "low", url, category="cors"))
    return out


_MIXED = re.compile(r"""(?:src|href|action)\s*=\s*["']http://""", re.IGNORECASE)


def detect_mixed_content(result) -> List[Finding]:
    url = _url(result)
    if not url.lower().startswith("https://"):
        return []
    m = _MIXED.search(_text(result))
    if m:
        return [make_finding("Mixed content: http resource on https page", "low", url,
                             category="mixed-content",
                             evidence={"example": m.group(0)[:60]})]
    return []


def detect_directory_listing(result) -> List[Finding]:
    text = _text(result)
    if re.search(r"<title>\s*Index of /", text, re.IGNORECASE) or ">Index of /" in text:
        return [make_finding("Directory listing enabled", "low", _url(result),
                             category="directory-listing")]
    return []


_REDIRECT_PARAMS = {"redirect", "redirect_uri", "redirecturl", "url", "next",
                    "return", "returnurl", "return_url", "dest", "destination",
                    "continue", "callback", "redir", "goto"}


def detect_open_redirect_params(result) -> List[Finding]:
    url = _url(result)
    params = {k.lower() for k, _ in parse_qsl(urlsplit(url).query)}
    hit = sorted(params & _REDIRECT_PARAMS)
    if hit:
        return [make_finding("Redirect-like parameter present (unverified)", "info", url,
                             category="open-redirect",
                             detail="A redirect-style parameter is present. Confirming an open "
                                    "redirect requires active testing, not done here.",
                             evidence={"params": ", ".join(hit)})]
    return []


def detect_cookie_prefixes(result, set_cookies: Optional[List[str]] = None) -> List[Finding]:
    url, h = _url(result), _headers(result)
    cookies = list(set_cookies) if set_cookies is not None else (
        [h["set-cookie"]] if "set-cookie" in h else [])
    out: List[Finding] = []
    for raw in cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = [p.strip().lower() for p in raw.split(";")[1:]]
        flags = {a.split("=")[0]: (a.split("=", 1)[1] if "=" in a else "") for a in attrs}
        low = name.lower()
        if low.startswith("__secure-") and "secure" not in flags:
            out.append(make_finding("__Secure- cookie without Secure flag", "low", url,
                                    category="cookie", evidence={"cookie": name}))
        if low.startswith("__host-"):
            if "secure" not in flags or "domain" in flags or flags.get("path", "") != "/":
                out.append(make_finding("__Host- cookie violates prefix rules", "low", url,
                                        category="cookie",
                                        detail="__Host- requires Secure, Path=/, and no Domain.",
                                        evidence={"cookie": name}))
    return out


def detect_weak_xfo(result) -> List[Finding]:
    url, h = _url(result), _headers(result)
    xfo = (h.get("x-frame-options") or "").strip().upper()
    if xfo and xfo not in ("DENY", "SAMEORIGIN"):
        return [make_finding("Weak or invalid X-Frame-Options value", "low", url,
                             category="security-headers",
                             detail=f"X-Frame-Options: {h.get('x-frame-options')} is not "
                                    f"DENY or SAMEORIGIN.")]
    return []
