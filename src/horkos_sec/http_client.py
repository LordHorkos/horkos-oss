"""
Guarded HTTP client — the one place requests leave the toolkit, safely.

Every request is:
  * checked by a RequestGuard (method + cap + scope + SSRF-safe resolution)
    BEFORE anything is sent — denied requests never touch the network;
  * throttled by an optional TokenBucket;
  * pinned to the exact IP the guard validated — the connection is made to that
    IP with the Host header and TLS SNI set to the original hostname, so DNS
    cannot hand back a different address between the check and the connect
    (the rebinding window the resolver's docs warn about);
  * attributed — caller-supplied headers (e.g. a researcher attribution header)
    go on every request;
  * recorded — method, status, headers, a capped body, timing, and the redirect
    chain come back in a FetchResult.

Redirects are NOT auto-followed by the transport: each hop is re-evaluated by the
guard, so a 3xx cannot bounce the client to an out-of-scope or private host.

This client sends only what the guard admits; with the default guard that is
GET/HEAD/OPTIONS. It is an observe-only fetcher, not an exploitation tool.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, urlunparse

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


@dataclass
class FetchResult:
    ok: bool
    url: str                       # original requested URL
    final_url: str                 # after redirects (== url if none)
    status: Optional[int] = None
    reason: str = ""               # denial/error reason when ok is False
    ip: str = ""                   # the pinned, validated address actually used
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    truncated: bool = False
    elapsed_s: float = 0.0
    redirects: List[str] = field(default_factory=list)


class GuardedHTTPClient:
    def __init__(self, guard, bucket=None, headers: Optional[Dict[str, str]] = None,
                 timeout: float = 10.0, max_body_bytes: int = 1 << 20,
                 max_redirects: int = 5, verify_tls: bool = True,
                 follow_redirects: bool = True, reuse_connections: bool = True):
        self._guard = guard
        self._bucket = bucket
        self._headers = dict(headers or {})
        self._timeout = timeout
        self._max_body = max_body_bytes
        self._max_redirects = max_redirects
        self._verify_tls = verify_tls
        self._follow = follow_redirects
        self._reuse = reuse_connections
        # One TLS context for the client's lifetime instead of one per request.
        self._ssl_ctx = ssl.create_default_context()
        if not verify_tls:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE
        # Keep-alive pool keyed by (scheme, host, pinned-ip, port). Single-threaded
        # use only; the controller gives each worker its own client (Phase 5).
        self._pool: Dict[tuple, object] = {}

    def close(self) -> None:
        for conn in self._pool.values():
            try:
                conn.close()
            except Exception:
                pass
        self._pool.clear()

    def fetch(self, url: str, method: str = "GET") -> FetchResult:
        method = method.upper()
        current = url
        chain: List[str] = []
        t0 = time.monotonic()

        for _ in range(self._max_redirects + 1):
            decision = self._guard.evaluate(current, method)
            if not decision.allowed:
                return FetchResult(False, url, current, reason=decision.reason,
                                   redirects=chain, elapsed_s=time.monotonic() - t0)

            ip = getattr(decision.resolved, "ip", "") or ""
            if not ip:
                return FetchResult(False, url, current,
                                   reason="guard returned no validated IP to pin to; "
                                          "wire the guard with safe_resolver.resolve",
                                   redirects=chain, elapsed_s=time.monotonic() - t0)

            if self._bucket is not None and not self._bucket.acquire(max_wait=self._timeout):
                return FetchResult(False, url, current, reason="rate limit / request budget exhausted",
                                   redirects=chain, elapsed_s=time.monotonic() - t0)

            try:
                status, headers, body, truncated = self._send(current, method, ip)
            except (OSError, ssl.SSLError, http.client.HTTPException) as e:
                return FetchResult(False, url, current, reason=f"transport error: {e}",
                                   ip=ip, redirects=chain, elapsed_s=time.monotonic() - t0)

            if self._follow and status in _REDIRECT_STATUSES and headers.get("location"):
                nxt = urljoin(current, headers["location"])
                chain.append(current)
                current = nxt
                continue  # re-guard the next hop

            return FetchResult(True, url, current, status=status, ip=ip,
                               headers=headers, body=body, truncated=truncated,
                               redirects=chain, elapsed_s=time.monotonic() - t0)

        return FetchResult(False, url, current, reason=f"too many redirects (>{self._max_redirects})",
                           redirects=chain, elapsed_s=time.monotonic() - t0)

    # ---- transport ---------------------------------------------------------

    def _new_conn(self, https: bool, ip: str, host: str, port: int):
        if https:
            return _PinnedHTTPSConnection(ip, host, port, self._timeout, self._ssl_ctx)
        return _PinnedHTTPConnection(ip, host, port, self._timeout)

    def _send(self, url: str, method: str, ip: str):
        parsed = urlparse(url)
        host = parsed.hostname or ""
        https = parsed.scheme == "https"
        port = parsed.port or (443 if https else 80)
        path = urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, ""))
        headers = {"Host": host, **self._headers}
        key = (parsed.scheme, host, ip, port)

        # Try a pooled connection first; a stale keep-alive socket fails on the
        # first use, so fall back to one fresh reconnect before giving up.
        conn = self._pool.pop(key, None) if self._reuse else None
        for attempt in (1, 2):
            if conn is None:
                conn = self._new_conn(https, ip, host, port)
            try:
                conn.request(method, path or "/", headers=headers)
                resp = conn.getresponse()
                raw = resp.read(self._max_body + 1)
                truncated = len(raw) > self._max_body
                body = raw[: self._max_body]
                hdrs = {k.lower(): v for k, v in resp.getheaders()}
                keep = (self._reuse and not resp.will_close)
                if keep:
                    self._pool[key] = conn        # reusable: back in the pool
                else:
                    conn.close()
                return resp.status, hdrs, body, truncated
            except (http.client.HTTPException, OSError) as e:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
                if attempt == 2:
                    raise e                        # reconnect also failed


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to a fixed IP while keeping the original hostname for Host header."""

    def __init__(self, ip, host, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._pin_ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._pin_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a fixed IP; TLS SNI and cert validation use the real hostname."""

    def __init__(self, ip, host, port, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pin_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pin_ip, self.port), self.timeout)
        # server_hostname = self.host (the real hostname) -> correct SNI + cert check
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
