#!/usr/bin/env python3
"""Phase 6: keyed audit log + report CWE/CVSS. Run: python3 test_phase6.py."""
import os
import sys
import tempfile

from horkos_sec.governance import AuditLog
from horkos_sec.report import build_report
from horkos_sec.controller import RunResult
from horkos_sec.run_config import build_run_plan, RunOptions
from horkos_sec.governance import Engagement
from horkos_sec.scope_guard import ScopeConfig
from horkos_sec.findings import make_finding


# ---- keyed audit -----------------------------------------------------------

def test_unkeyed_default_still_works():
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    log = AuditLog(p)
    log.record("request", url="https://example.com/a")
    ok, bad = AuditLog.verify(p)
    assert ok and bad is None


def test_keyed_log_verifies_with_key():
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    key = b"super-secret-key"
    log = AuditLog(p, key=key)
    log.record("request", url="https://example.com/a")
    log.record("request", url="https://example.com/b")
    assert AuditLog.verify(p, key=key)[0]


def test_keyed_log_fails_without_key():
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    key = b"k"
    AuditLog(p, key=key).record("request", url="https://example.com/a")
    ok, bad = AuditLog.verify(p)                 # no key supplied
    assert not ok and bad == 1


def test_keyed_log_fails_with_wrong_key():
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    AuditLog(p, key=b"right").record("request", url="https://example.com/a")
    assert not AuditLog.verify(p, key=b"wrong")[0]


def test_keyed_forgery_without_key_detected():
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    key = b"k"
    log = AuditLog(p, key=key)
    log.record("request", url="https://example.com/a")
    log.record("request", url="https://example.com/b")
    # attacker rewrites a line and recomputes a plain sha256 chain (no key)
    import hashlib, json
    lines = [json.loads(x) for x in open(p).read().splitlines()]
    lines[0]["url"] = "https://evil.test/x"
    prev = "0" * 64
    out = []
    for e in lines:
        e.pop("h")
        payload = json.dumps(e, sort_keys=True, separators=(",", ":"))
        e["h"] = hashlib.sha256((prev + payload).encode()).hexdigest()
        prev = e["h"]
        out.append(json.dumps(e, sort_keys=True, separators=(",", ":")))
    open(p, "w").write("\n".join(out) + "\n")
    assert not AuditLog.verify(p, key=key)[0]    # HMAC verify rejects the forgery


# ---- report CWE/CVSS -------------------------------------------------------

def _result(findings):
    eng = Engagement("acme", ScopeConfig(allowed_domains=["example.com"],
                                         allowed_schemes=["https"]),
                     authorized=True, modes=("observe",))
    plan = build_run_plan(eng, ["https://example.com/"], RunOptions())
    r = RunResult(plan=plan)
    r.findings = findings
    return r


def test_report_includes_cwe_and_cvss():
    f = make_finding("CORS allows any origin with credentials", "medium",
                     "https://example.com/x", category="cors")
    md = build_report(_result([f]))
    assert "CWE-942" in md
    assert "CVSS 7.5" in md


def test_report_prefix_mapped_finding():
    f = make_finding("AWS access key exposed in response", "medium",
                     "https://example.com/x", category="body-secret")
    md = build_report(_result([f]))
    assert "CWE-312" in md


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
