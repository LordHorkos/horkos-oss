# http-client

The one place requests leave the toolkit — and the only one that should. Every
request is gated, throttled, pinned, attributed, and recorded.

## What it guarantees

- **Gated before send.** Each request (and each redirect hop) is checked by a
  `RequestGuard` first; a denied request never touches the network.
- **IP-pinned.** The connection is made to the exact address the guard
  validated, with the `Host` header and TLS SNI set to the real hostname — so DNS
  can't swap in a different address between the check and the connect.
- **Re-guarded redirects.** 3xx responses are not auto-followed by the transport;
  each hop is re-evaluated, so a redirect can't bounce you to an out-of-scope or
  private host.
- **Throttled.** An optional `TokenBucket` is acquired before each send.
- **Attributed + recorded.** Caller headers go on every request; the response
  comes back as a `FetchResult` (status, headers, capped body, timing, redirect
  chain).

It sends only what the guard admits — with the default guard, GET/HEAD/OPTIONS.
It is an observe-only fetcher, not an exploitation tool.

## Usage

```python
from functools import partial
from horkos_sec import (
    GuardedHTTPClient, RequestGuard, TokenBucket,
    resolve, check_scope, parse_hackerone_scope,
)

scope = parse_hackerone_scope(pasted_scope).config
guard = RequestGuard(
    scope_check=partial(check_scope, scope=scope),
    resolve=resolve,                      # supplies the validated IP the client pins to
    max_requests=500,
)
client = GuardedHTTPClient(
    guard,
    bucket=TokenBucket(rate=0.3, burst=3, max_requests=500),
    headers={"X-HackerOne-Research": "your-handle"},   # attribution on every request
    timeout=10.0,
)

r = client.fetch("https://api.example.com/health")
if r.ok:
    print(r.status, r.headers.get("server"), len(r.body), "via", r.ip)
else:
    print("refused/failed:", r.reason)
```

The guard must be wired with `safe_resolver.resolve` (or any resolver whose
result carries `.ip`), because the client pins to `decision.resolved.ip`. Without
a validated IP it refuses rather than falling back to an unpinned connect.

## FetchResult

`ok`, `url`, `final_url`, `status`, `reason`, `ip`, `headers` (lower-cased),
`body` (bytes, capped at `max_body_bytes`), `truncated`, `elapsed_s`,
`redirects` (the hop chain).

## Options

`timeout`, `max_body_bytes` (default 1 MiB), `max_redirects` (default 5),
`follow_redirects`, `verify_tls` (keep `True` for real targets).

## Tests

```bash
python3 tests/test_http_client.py     # or: python -m pytest
```
Tests run against a loopback server — no outbound network.
