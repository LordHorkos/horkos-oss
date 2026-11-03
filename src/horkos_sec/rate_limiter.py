"""
Token bucket rate limiter.
Thread-safe. Enforces a per-second rate AND a global request cap.
"""

import time
import threading


class TokenBucket:
    """
    Token bucket algorithm.
    - Tokens refill at `rate` per second up to `burst` capacity.
    - Each acquire() consumes one token.
    - Blocks if no tokens available (up to max_wait seconds).
    """

    def __init__(self, rate: float, burst: int, max_requests: int):
        self._rate = rate           # tokens per second
        self._burst = burst         # max burst capacity
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()
        self._total_consumed = 0
        self._max_requests = max_requests

    def acquire(self, max_wait: float = 30.0) -> bool:
        """
        Try to acquire a token. Blocks up to max_wait seconds.
        Returns False if max_requests reached or wait exceeded.
        """
        deadline = time.monotonic() + max_wait
        while True:
            with self._lock:
                self._refill()
                if self._total_consumed >= self._max_requests:
                    return False
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    self._total_consumed += 1
                    return True
                wait_time = (1.0 - self._tokens) / self._rate
            # Out of lock: sleep and retry
            if time.monotonic() + wait_time > deadline:
                return False
            time.sleep(min(wait_time, 0.1))

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            float(self._burst),
            self._tokens + elapsed * self._rate
        )
        self._last_refill = now

    @property
    def consumed(self) -> int:
        return self._total_consumed

    @property
    def exhausted(self) -> bool:
        return self._total_consumed >= self._max_requests


class HostRateLimiter:
    """Per-host rate limiting with one shared global lifetime cap.

    Each host gets its own TokenBucket (its own rate/burst), so a slow host does
    not starve others and politeness is enforced per host. One shared counter
    enforces the total request ceiling across all hosts. Thread-safe.
    """

    def __init__(self, rate: float, burst: int, global_max_requests: int):
        self._rate = rate
        self._burst = burst
        self._global_max = global_max_requests
        self._lock = threading.Lock()
        self._buckets = {}
        self._global_consumed = 0

    def _bucket(self, host: str) -> TokenBucket:
        with self._lock:
            b = self._buckets.get(host)
            if b is None:
                # per-host bucket does the rate; the global cap is enforced here
                b = TokenBucket(self._rate, self._burst, self._global_max)
                self._buckets[host] = b
            return b

    def acquire(self, host: str, max_wait: float = 30.0) -> bool:
        with self._lock:
            if self._global_consumed >= self._global_max:
                return False
        if not self._bucket(host).acquire(max_wait=max_wait):
            return False
        with self._lock:
            if self._global_consumed >= self._global_max:
                return False
            self._global_consumed += 1
            return True

    @property
    def consumed(self) -> int:
        with self._lock:
            return self._global_consumed
