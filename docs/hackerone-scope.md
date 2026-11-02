# hackerone-scope

Paste a HackerOne program's scope and get a ready-to-use `ScopeConfig` — so the
request guard runs on the program's own parameters instead of a hand-written
allowlist.

## Usage

```python
from horkos_sec import parse_hackerone_scope, check_scope

pasted = open("scope.json").read()      # or the scope table copied from the page
parsed = parse_hackerone_scope(pasted)

print(parsed.summary())                 # "3 wildcard, 2 exact host, 1 out-of-scope, 4 skipped"
cfg = parsed.config                     # a ScopeConfig

check_scope("https://api.example.com/v1", cfg)   # ScopeResult(in_scope=...)
```

`parsed.config` drops straight into [`request-guard`](request-guard.md):

```python
from functools import partial
from horkos_sec import RequestGuard, resolve, check_scope
guard = RequestGuard(scope_check=partial(check_scope, scope=parsed.config),
                     resolve=resolve, max_requests=500)
```

## Accepted input

Auto-detected:

1. **Structured-scopes JSON** from the HackerOne API
   (`.../programs/<handle>/structured_scopes`) — the `{"data": [...]}` envelope
   or a bare list of attribute objects.
2. **A list of asset objects** — `[{"asset_identifier", "asset_type",
   "eligible_for_submission"}, ...]`.
3. **Plain text** — one asset per line, as copied from the scope table. Out of
   scope is detected from an "out of scope" / "excluded" marker on the line or a
   leading `-`.

## Mapping

| HackerOne asset | Becomes |
|---|---|
| `*.example.com` / `.example.com`, eligible | `allowed_domains` (subtree) |
| `example.com` / `api.example.com` (bare host or URL), eligible | `allowed_exact` (exact host) |
| any of the above, **not** eligible | `disallowed_domains` (wildcard → subtree block, host → exact block) |
| non-web asset (CIDR, IP range, mobile package, repo, `OTHER`, …) | **skipped**, listed in `parsed.skipped` |

Only web assets (`URL`, `WILDCARD`, `DOMAIN`, `API`, `WEBSITE`) are mapped. A URL
scope guard has nothing safe to do with a `com.example.app` package id or a CIDR
block, so those are reported in `parsed.skipped` rather than guessed at.

## Deliberately conservative

The parser never widens scope on a guess. Anything it can't confidently classify
is skipped and surfaced in `parsed.skipped` for you to review, and the resulting
`ScopeConfig` is still enforced fail-closed by `scope_guard`. It raises
`ValueError` on empty input or a scope with no usable web assets, rather than
returning an empty (deny-all or, worse, accidentally broad) config.

**It does not interpret freeform instructions or act on its own.** It turns a
pasted scope into a config; what runs against that scope is still the explicit
code you wire up (guard + resolver + rate limiter).

## Tests

```bash
python3 tests/test_hackerone_scope.py     # or: python -m pytest
```
