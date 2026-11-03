"""
Passive body detectors — scan a response body (what a normal GET returned) for
things that shouldn't be exposed. No injection, no mutation: this only reads.

Covered:
  * exposed credentials — private-key blocks, AWS keys, Google API keys,
    GitHub/Slack tokens, JWTs
  * verbose errors / stack traces — framework error pages that leak internals
  * internal addresses — RFC1918 / loopback IPs disclosed in the body
  * risky code comments — HTML/JS comments mentioning password/secret/key/TODO
  * email harvesting — several distinct addresses exposed

Findings are capped into the model band by make_finding; a live private key is
reported medium, most else low/info. Matched secrets are masked in the evidence
(type + a short fingerprint), never stored whole.
"""

from __future__ import annotations

import re
from typing import List

from .findings import Finding, make_finding

_MAX_SCAN = 1 << 20  # scan at most 1 MiB of body text

# (title, severity, compiled regex). Ordered; each fires at most once per URL.
_SECRET_PATTERNS = [
    ("Private key exposed in response", "medium",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("AWS access key exposed in response", "medium",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key exposed in response", "medium",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("GitHub token exposed in response", "medium",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("Slack token exposed in response", "medium",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("JWT exposed in response", "low",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b")),
]

_STACK_MARKERS = (
    "traceback (most recent call last)", "at java.", "at org.", "at com.",
    "system.web", "stack trace:", "fatal error:", "warning:",
    "sqlstate", "ora-0", "psql:", "exception in thread",
    "undefined index", "notice: undefined", "nullpointerexception",
)

_RFC1918 = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

_COMMENT = re.compile(r"<!--(.*?)-->|/\*(.*?)\*/", re.DOTALL)
_COMMENT_KEYWORDS = re.compile(
    r"\b(pass(word|wd)?|secret|api[_-]?key|token|credential|backdoor|todo|fixme)\b",
    re.IGNORECASE)

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


def _url(result) -> str:
    return getattr(result, "final_url", None) or getattr(result, "url", "") or ""


def _text(result) -> str:
    body = getattr(result, "body", b"") or b""
    if isinstance(body, bytes):
        body = body[:_MAX_SCAN].decode("utf-8", "replace")
    return body[:_MAX_SCAN]


def _mask(s: str) -> str:
    s = s.strip()
    if len(s) <= 10:
        return s[:2] + "…"
    return f"{s[:4]}…{s[-4:]} (len {len(s)})"


def detect_body(result) -> List[Finding]:
    url = _url(result)
    text = _text(result)
    if not text:
        return []
    low = text.lower()
    out: List[Finding] = []

    for title, sev, rx in _SECRET_PATTERNS:
        m = rx.search(text)
        if m:
            out.append(make_finding(title, sev, url, category="body-secret",
                                    detail="Sensitive token pattern found in the response body.",
                                    evidence={"match": _mask(m.group(0))}))

    if any(mk in low for mk in _STACK_MARKERS):
        hit = next(mk for mk in _STACK_MARKERS if mk in low)
        out.append(make_finding("Verbose error / stack trace exposed", "low", url,
                                category="body-error",
                                detail="Response body contains error/stack-trace output.",
                                evidence={"marker": hit}))

    ip = _RFC1918.search(text)
    if ip:
        out.append(make_finding("Internal IP address disclosed in body", "info", url,
                                category="body-info",
                                evidence={"ip": ip.group(0)}))

    for m in _COMMENT.finditer(text):
        comment = (m.group(1) or m.group(2) or "")
        if _COMMENT_KEYWORDS.search(comment):
            out.append(make_finding("Sensitive keyword in code comment", "low", url,
                                    category="body-comment",
                                    detail="An HTML/JS comment mentions a credential-like keyword.",
                                    evidence={"snippet": comment.strip()[:80]}))
            break

    emails = []
    seen = set()
    for m in _EMAIL.finditer(text):
        e = m.group(0).lower()
        if e not in seen:
            seen.add(e)
            emails.append(e)
    if len(emails) >= 3:
        out.append(make_finding("Multiple email addresses exposed", "info", url,
                                category="body-info",
                                detail=f"{len(emails)} distinct email addresses in the response.",
                                evidence={"sample": ", ".join(emails[:5])}))

    return out
