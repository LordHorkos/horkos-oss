"""
Request guard — a final fail-closed gate before an outbound HTTP request.

Aggregates four checks in a fixed order and refuses on the first failure:
  1. method      — must be in an allowed, non-mutating set
  2. request cap — a hard ceiling on total allowed requests
  3. scope       — the URL must be in scope
  4. resolution  — the host must resolve to an address the caller accepts
                   (e.g. not private/loopback/link-local, for SSRF safety)

Scope-checking and host resolution are injected as callables, so this module
carries no dependency on any particular scope format or resolver. Supply your
own; two small result protocols (ScopeResult, ResolvedResult) define the shape
the guard reads.

Only the method and cap checks mutate state (the request counter), and only on
a full `evaluate()` that passes every check. `is_allowed()` is a cheap
scope-only probe for planning (crawl seeds, discovery) — it consumes no budget
and does no resolution.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Protocol
from urllib.parse import urlparse

ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class ScopeResult(Protocol):
    in_scope: bool
    reason: str


class ResolvedResult(Protocol):
    is_valid: bool
    denial_reason: str


# Injected callables:
#   scope_check(url) -> ScopeResult
#   resolve(hostname) -> ResolvedResult
ScopeCheck = Callable[[str], ScopeResult]
Resolve = Callable[[str], ResolvedResult]


@dataclass
class GuardDecision:
    allowed: bool
    reasons: List[str] = field(default_factory=list)
    resolved: Optional[ResolvedResult] = None

    @property
    def reason(self) -> str:
        return "; ".join(self.reasons) if self.reasons else "allowed"


class RequestGuard:
    def __init__(self, scope_check: ScopeCheck, resolve: Resolve, max_requests: int):
        self._scope_check = scope_check
        self._resolve = resolve
        self._max_requests = max_requests
        self._request_count = 0
        self._lock = threading.Lock()

    def evaluate(self, url: str, method: str = "GET") -> GuardDecision:
        """
        Full pre-flight check for a proposed request.
        Returns GuardDecision(allowed=False, ...) on ANY failure.

        Thread-safe: the budget slot is reserved atomically before the slow
        scope/resolve steps and released if any of them deny, so concurrent
        workers can never together exceed max_requests (a strict cap) and a
        denied request still consumes nothing.
        """
        # 1. Method check (no budget involved)
        if method.upper() not in ALLOWED_METHODS:
            return GuardDecision(
                False,
                [f"Method '{method}' not in allowed set {sorted(ALLOWED_METHODS)}."],
            )

        # 2. Reserve a budget slot atomically (strict cap under concurrency)
        with self._lock:
            if self._request_count >= self._max_requests:
                return GuardDecision(False, [f"Max requests ({self._max_requests}) reached."])
            self._request_count += 1

        try:
            # 3. Scope check (URL level)
            scope_result = self._scope_check(url)
            if not scope_result.in_scope:
                return self._release(GuardDecision(False, [f"Scope violation: {scope_result.reason}"]))

            # 4. Host resolution / IP validation
            try:
                hostname = urlparse(url).hostname or ""
            except Exception as e:
                return self._release(GuardDecision(False, [f"URL parse error: {e}"]))

            resolved = self._resolve(hostname)
            if not resolved.is_valid:
                return self._release(
                    GuardDecision(False, [f"IP validation failed: {resolved.denial_reason}"], resolved))

            # All checks passed — keep the reserved slot and allow
            return GuardDecision(True, [], resolved)
        except BaseException:
            self._release(None)
            raise

    def _release(self, decision):
        """Return a reserved budget slot (used when a reserved request is denied)."""
        with self._lock:
            self._request_count -= 1
        return decision

    @property
    def request_count(self) -> int:
        with self._lock:
            return self._request_count

    def is_allowed(self, url: str) -> bool:
        """
        Cheap scope-only check for use during URL planning (crawl seeds,
        discovery). Returns True if the URL is in scope. Does NOT consume the
        request budget and does NOT resolve the host — those are full-flight
        checks performed by evaluate() at request time. Fails closed on error.
        """
        try:
            return self._scope_check(url).in_scope
        except Exception:
            return False
