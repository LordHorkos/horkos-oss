# horkos-oss

Open-source security work by **HORKOS** — fixes, tools, and research released publicly.

## Contents

| Path | What it is | Status |
|---|---|---|
| [`upstream-fixes/rbenv-utf8-bom`](upstream-fixes/rbenv-utf8-bom) | rbenv fails to read a `.ruby-version` file saved with a UTF-8 byte order mark | Submitted upstream: [rbenv#1665](https://github.com/rbenv/rbenv/pull/1665) |
| [`lib/severity-band`](lib/severity-band) | Cap findings into a restricted severity band without silently dropping high/critical results | Released |
| [`lib/rate-limiter`](lib/rate-limiter) | Thread-safe token-bucket limiter enforcing a per-second rate and a global request cap | Released |
| [`lib/request-guard`](lib/request-guard) | Fail-closed pre-flight gate for outbound HTTP: method, cap, scope, and SSRF-safe resolution | Released |
| [`lib/safe-resolver`](lib/safe-resolver) | SSRF-safe DNS resolver: validates every resolved address against private/non-routable ranges | Released |
| [`lib/scope-guard`](lib/scope-guard) | In-scope URL decision with allow/deny domain matching and subtree rules | Released |
| [`tools/scrubber`](tools/scrubber) | Redact a source tree before open-sourcing it | Released |

## Composing the request-safety toolkit

Five of the `lib/` modules click together into one safe outbound-HTTP path:
`scope-guard` and `safe-resolver` plug into `request-guard`'s injected
`scope_check` and `resolve`, and `rate-limiter` throttles what the guard admits.

```python
from functools import partial
from scope_guard import ScopeConfig, check_scope   # lib/scope-guard
from safe_resolver import resolve                   # lib/safe-resolver
from request_guard import RequestGuard              # lib/request-guard
from rate_limiter import TokenBucket                # lib/rate-limiter

scope = ScopeConfig(allowed_domains=["example.com"], allowed_schemes=["https"])

guard = RequestGuard(
    scope_check=partial(check_scope, scope=scope),
    resolve=resolve,
    max_requests=500,
)
bucket = TokenBucket(rate=0.3, burst=3, max_requests=500)

def fetch(url):
    decision = guard.evaluate(url)         # method + cap + scope + SSRF-safe resolve
    if not decision.allowed:
        return None, decision.reason
    if not bucket.acquire(max_wait=30.0):
        return None, "rate/budget exhausted"
    return do_request(url, decision.resolved.ip), None
```

The guard refuses non-GET/HEAD/OPTIONS, out-of-scope URLs, and hosts that resolve to
private/non-routable addresses — each fail-closed, before any byte leaves.

## Layout

- `upstream-fixes/` — bugs found in third-party open-source projects, each with a root-cause write-up, a patch that applies to upstream, and verification results.
  - Each fix has `upstream.conf` (repo + ref) and `ci.sh`. The [Upstream fixes](.github/workflows/upstream-fixes.yml) workflow clones upstream, applies the patch, and runs the project's own test suite on Ubuntu, macOS, and macOS with the system bash 3.2. It re-runs weekly to catch upstream drift.

All pushes are scanned for leaked secrets by [gitleaks](.github/workflows/secret-scan.yml).

## Reporting

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Patches under `upstream-fixes/` are offered to their upstream projects under those projects' own licenses.
