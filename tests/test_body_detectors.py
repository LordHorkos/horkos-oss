#!/usr/bin/env python3
"""Standalone tests for body_detectors.py. Run: python3 test_body_detectors.py."""
import sys
from dataclasses import dataclass, field
from typing import Dict

from horkos_sec.body_detectors import detect_body


@dataclass
class R:
    url: str = "https://example.com/"
    final_url: str = "https://example.com/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""


def _titles(fs):
    return {f.title for f in fs}


def test_private_key_detected_medium():
    fs = detect_body(R(body=b"x -----BEGIN RSA PRIVATE KEY-----\nAAAA"))
    assert "Private key exposed in response" in _titles(fs)
    f = next(f for f in fs if f.title == "Private key exposed in response")
    assert f.severity == "medium"


def test_aws_and_google_keys():
    fs = detect_body(R(body=b"AKIAIOSFODNN7EXAMPLE and AIza" + b"a" * 35))
    t = _titles(fs)
    assert "AWS access key exposed in response" in t
    assert "Google API key exposed in response" in t


def test_jwt_low():
    jwt = b"eyJhbGciOiJExxxxx.eyJzdWIiOjEyfQ.ZZZZsignature"
    fs = detect_body(R(body=jwt))
    assert "JWT exposed in response" in _titles(fs)


def test_secret_is_masked_not_stored_whole():
    fs = detect_body(R(body=b"AKIAIOSFODNN7EXAMPLE"))
    f = next(f for f in fs if "AWS" in f.title)
    assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence["match"]
    assert "…" in f.evidence["match"]


def test_stack_trace_detected():
    fs = detect_body(R(body=b"<pre>Traceback (most recent call last):\n  File ...</pre>"))
    assert "Verbose error / stack trace exposed" in _titles(fs)


def test_internal_ip_detected():
    fs = detect_body(R(body=b"backend at 10.1.2.3 failed"))
    assert "Internal IP address disclosed in body" in _titles(fs)


def test_comment_keyword_detected():
    fs = detect_body(R(body=b"<!-- TODO: remove hardcoded password before launch -->"))
    assert "Sensitive keyword in code comment" in _titles(fs)


def test_emails_threshold():
    one = detect_body(R(body=b"contact a@x.com"))
    assert "Multiple email addresses exposed" not in _titles(one)   # below threshold
    many = detect_body(R(body=b"a@x.com b@y.com c@z.com d@w.com"))
    assert "Multiple email addresses exposed" in _titles(many)


def test_clean_body_no_findings():
    assert detect_body(R(body=b"<html><body>hello world</body></html>")) == []


def test_empty_body_no_findings():
    assert detect_body(R(body=b"")) == []


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
