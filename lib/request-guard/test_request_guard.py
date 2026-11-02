#!/usr/bin/env python3
"""Standalone tests for request_guard.py. Run: python3 test_request_guard.py."""
import sys
from dataclasses import dataclass

from request_guard import RequestGuard, GuardDecision


@dataclass
class Scope:
    in_scope: bool
    reason: str = ""


@dataclass
class Resolved:
    is_valid: bool
    denial_reason: str = ""


def _guard(in_scope=True, valid=True, max_requests=100):
    return RequestGuard(
        scope_check=lambda url: Scope(in_scope, "" if in_scope else "out of scope"),
        resolve=lambda host: Resolved(valid, "" if valid else "private IP"),
        max_requests=max_requests,
    )


def test_allows_clean_get():
    d = _guard().evaluate("https://example.com/a")
    assert d.allowed and d.reason == "allowed", d


def test_rejects_mutating_method_first():
    g = _guard()
    d = g.evaluate("https://example.com/a", method="POST")
    assert not d.allowed and "Method" in d.reason
    assert g.request_count == 0, "a rejected request must not consume budget"


def test_method_check_precedes_scope():
    # out of scope AND bad method -> method reason wins (ordering)
    d = _guard(in_scope=False).evaluate("https://x/a", method="DELETE")
    assert "Method" in d.reason, d.reason


def test_scope_violation_blocks():
    d = _guard(in_scope=False).evaluate("https://evil.test/a")
    assert not d.allowed and "Scope violation" in d.reason


def test_ip_validation_blocks():
    d = _guard(valid=False).evaluate("https://internal.test/a")
    assert not d.allowed and "IP validation failed" in d.reason
    assert d.resolved is not None and not d.resolved.is_valid


def test_request_cap_enforced_and_no_overspend():
    g = _guard(max_requests=2)
    assert g.evaluate("https://example.com/1").allowed
    assert g.evaluate("https://example.com/2").allowed
    d = g.evaluate("https://example.com/3")
    assert not d.allowed and "Max requests" in d.reason
    assert g.request_count == 2


def test_only_passing_evaluate_consumes_budget():
    g = _guard(valid=False)
    g.evaluate("https://example.com/a")   # fails at resolution
    assert g.request_count == 0


def test_is_allowed_is_scope_only_and_no_budget():
    g = _guard(valid=False, max_requests=1)
    assert g.is_allowed("https://example.com/a") is True   # scope ok, ignores resolution
    assert g.request_count == 0                            # no budget consumed


def test_is_allowed_fails_closed_on_scope_error():
    g = RequestGuard(scope_check=lambda u: (_ for _ in ()).throw(RuntimeError("boom")),
                     resolve=lambda h: Resolved(True), max_requests=10)
    assert g.is_allowed("https://example.com/a") is False


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
