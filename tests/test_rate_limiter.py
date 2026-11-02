#!/usr/bin/env python3
"""Standalone tests for rate_limiter.py. Run: python3 test_rate_limiter.py."""
import sys
import time

from horkos_sec.rate_limiter import TokenBucket


def test_burst_available_immediately():
    tb = TokenBucket(rate=1.0, burst=5, max_requests=100)
    t0 = time.monotonic()
    got = sum(tb.acquire(max_wait=0.0) for _ in range(5))
    assert got == 5, got
    assert time.monotonic() - t0 < 0.1, "full burst must not block"


def test_max_requests_cap_enforced():
    tb = TokenBucket(rate=1000.0, burst=10, max_requests=3)
    assert sum(tb.acquire(max_wait=0.1) for _ in range(10)) == 3
    assert tb.exhausted
    assert tb.consumed == 3


def test_acquire_returns_false_when_wait_exceeds_deadline():
    tb = TokenBucket(rate=1.0, burst=1, max_requests=100)
    assert tb.acquire(max_wait=0.0) is True          # consume the one token
    t0 = time.monotonic()
    assert tb.acquire(max_wait=0.0) is False          # no tokens, no wait budget
    assert time.monotonic() - t0 < 0.1


def test_refill_over_time():
    tb = TokenBucket(rate=50.0, burst=1, max_requests=100)
    assert tb.acquire(max_wait=0.0) is True
    assert tb.acquire(max_wait=0.0) is False
    time.sleep(0.1)                                   # ~5 tokens refilled
    assert tb.acquire(max_wait=0.0) is True


def test_refill_capped_at_burst():
    tb = TokenBucket(rate=1000.0, burst=2, max_requests=100)
    time.sleep(0.05)                                  # would refill many, capped at 2
    got = sum(tb.acquire(max_wait=0.0) for _ in range(5))
    assert got == 2, got


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
