#!/usr/bin/env python3
"""Standalone tests for governance.py. Run: python3 test_governance.py."""
import os
import sys
import tempfile
import threading

from horkos_sec.governance import (
    Engagement, authorize, AuditLog, KillSwitch, Aborted,
)
from horkos_sec.scope_guard import ScopeConfig


def _scope():
    return ScopeConfig(allowed_domains=["example.com"], allowed_schemes=["https"])


# ---- authorization ---------------------------------------------------------

def test_unauthorized_engagement_denied():
    e = Engagement("acme", _scope(), authorized=False)
    d = authorize(e, "https://example.com/a")
    assert not d.allowed and "not confirmed authorized" in d.reason


def test_authorized_in_scope_allowed():
    e = Engagement("acme", _scope(), authorized=True)
    assert authorize(e, "https://example.com/a").allowed


def test_out_of_scope_denied_even_if_authorized():
    e = Engagement("acme", _scope(), authorized=True)
    d = authorize(e, "https://evil.test/a")
    assert not d.allowed and "out of scope" in d.reason


def test_mode_must_be_permitted():
    e = Engagement("acme", _scope(), authorized=True, modes=("observe",))
    assert authorize(e, "https://example.com/a", mode="observe").allowed
    d = authorize(e, "https://example.com/a", mode="validate")
    assert not d.allowed and "mode" in d.reason


# ---- audit log -------------------------------------------------------------

def test_audit_appends_and_verifies():
    p = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
    log = AuditLog(p)
    log.record("request", url="https://example.com/a", status=200)
    log.record("request", url="https://example.com/b", status=404)
    ok, bad = AuditLog.verify(p)
    assert ok and bad is None


def test_audit_chain_detects_tampering():
    p = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
    log = AuditLog(p)
    log.record("request", url="https://example.com/a", status=200)
    log.record("request", url="https://example.com/b", status=200)
    lines = open(p).read().splitlines()
    lines[0] = lines[0].replace('"status":200', '"status":500')
    open(p, "w").write("\n".join(lines) + "\n")
    ok, bad = AuditLog.verify(p)
    assert not ok and bad == 1


def test_audit_chain_detects_deletion():
    p = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
    log = AuditLog(p)
    for i in range(3):
        log.record("request", url=f"https://example.com/{i}")
    lines = open(p).read().splitlines()
    del lines[1]                                   # drop the middle entry
    open(p, "w").write("\n".join(lines) + "\n")
    ok, bad = AuditLog.verify(p)
    assert not ok and bad == 2


def test_audit_resumes_chain_across_instances():
    p = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
    AuditLog(p).record("request", url="https://example.com/a")
    AuditLog(p).record("request", url="https://example.com/b")   # new instance, same file
    ok, _ = AuditLog.verify(p)
    assert ok


def test_audit_threadsafe():
    p = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
    log = AuditLog(p)
    def worker(k):
        for i in range(20):
            log.record("request", url=f"https://example.com/{k}-{i}")
    ts = [threading.Thread(target=worker, args=(k,)) for k in range(5)]
    [t.start() for t in ts]; [t.join() for t in ts]
    ok, bad = AuditLog.verify(p)
    assert ok, f"chain broke at {bad}"
    assert len(open(p).read().splitlines()) == 100


# ---- kill switch -----------------------------------------------------------

def test_killswitch_trip():
    k = KillSwitch()
    assert not k.tripped
    k.check()                                      # no raise
    k.trip("stop now")
    assert k.tripped
    try:
        k.check()
    except Aborted as e:
        assert "stop now" in str(e)
        return
    raise AssertionError("check() must raise after trip")


def test_killswitch_file_sentinel():
    p = os.path.join(tempfile.mkdtemp(), "STOP")
    k = KillSwitch(path=p)
    assert not k.tripped
    open(p, "w").write("halt")                     # external trip via file
    assert k.tripped
    try:
        k.check()
    except Aborted:
        return
    raise AssertionError("sentinel file must trip the switch")


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
