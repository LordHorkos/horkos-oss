# horkos-oss

Open-source security work by **HORKOS** — fixes, tools, and research released publicly.

## Contents

The `horkos_sec` package (under `src/`) is a dependency-free request-safety toolkit.

| Module | What it is | Docs |
|---|---|---|
| `horkos_sec.scope_guard` | In-scope URL decision with allow/deny domain matching and subtree rules | [docs](docs/scope-guard.md) |
| `horkos_sec.safe_resolver` | SSRF-safe DNS resolver: validates every resolved address against private/non-routable ranges | [docs](docs/safe-resolver.md) |
| `horkos_sec.request_guard` | Fail-closed pre-flight gate for outbound HTTP: method, cap, scope, and SSRF-safe resolution | [docs](docs/request-guard.md) |
| `horkos_sec.rate_limiter` | Thread-safe token-bucket limiter enforcing a per-second rate and a global request cap | [docs](docs/rate-limiter.md) |
| `horkos_sec.severity` | Cap findings into a restricted severity band without silently dropping high/critical results | [docs](docs/severity-band.md) |
| `horkos_sec.hackerone_scope` | Parse a pasted HackerOne program scope (JSON or text) into a ready-to-run `ScopeConfig` | [docs](docs/hackerone-scope.md) |
| `horkos_sec.http_client` | Guarded, IP-pinned, attributed, recorded HTTP fetcher — the one safe egress point | [docs](docs/http-client.md) |
| `horkos_sec.governance` | Authorization gate, tamper-evident audit log, and kill switch for accountable live runs | [docs](docs/governance.md) |
| `horkos_sec.run_config` | Target intake: authorize seeds into a validated `RunPlan` with a safe rate ceiling | [docs](docs/run-config.md) |

Other contents:

| Path | What it is | Status |
|---|---|---|
| [`upstream-fixes/rbenv-utf8-bom`](upstream-fixes/rbenv-utf8-bom) | rbenv fails to read a `.ruby-version` file saved with a UTF-8 byte order mark | Submitted upstream: [rbenv#1665](https://github.com/rbenv/rbenv/pull/1665) |
| [`tools/scrubber`](tools/scrubber) | Redact a source tree before open-sourcing it | Released |

## Install

```bash
pip install -e .          # from a checkout
python -m pytest          # run the test suite
```

## Composing the request-safety toolkit

The five modules click together into one safe outbound-HTTP path: `scope_guard`
and `safe_resolver` plug into `request_guard`'s injected `scope_check` and
`resolve`, and `rate_limiter` throttles what the guard admits.

```python
from functools import partial
from horkos_sec import (
    ScopeConfig, check_scope, resolve, RequestGuard, TokenBucket,
)

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

To build `scope` from a program's own scope instead of a hand-written allowlist,
paste the HackerOne scope (JSON or the copied table) through `parse_hackerone_scope`:

```python
from horkos_sec import parse_hackerone_scope
scope = parse_hackerone_scope(pasted_scope_text).config
```

## Layout

- `upstream-fixes/` — bugs found in third-party open-source projects, each with a root-cause write-up, a patch that applies to upstream, and verification results.
  - Each fix has `upstream.conf` (repo + ref) and `ci.sh`. The [Upstream fixes](.github/workflows/upstream-fixes.yml) workflow clones upstream, applies the patch, and runs the project's own test suite on Ubuntu, macOS, and macOS with the system bash 3.2. It re-runs weekly to catch upstream drift.

All pushes are scanned for leaked secrets by [gitleaks](.github/workflows/secret-scan.yml).

## Reporting

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Patches under `upstream-fixes/` are offered to their upstream projects under those projects' own licenses.
