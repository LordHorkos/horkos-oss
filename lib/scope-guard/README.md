# scope-guard

Decide whether a URL is in scope before any request is made. Fail-closed:
anything unparseable or ambiguous is denied. A URL is in scope only if it parses
with a scheme and host, its scheme is allowed, its host matches an allowed
domain, and its host matches no disallowed domain (an explicit block wins).

## Usage

```python
from scope_guard import ScopeConfig, check_scope

scope = ScopeConfig(
    allowed_domains=["example.com"],          # root + subdomains by default
    disallowed_domains=[".internal.example.com"],
    allowed_schemes=["https"],
)

r = check_scope("https://api.example.com/v1", scope)
if r.in_scope:
    proceed()
else:
    reject(r.reason)
```

Drops straight into [`request-guard`](../request-guard) as its injected
`scope_check`:

```python
from functools import partial
guard = RequestGuard(scope_check=partial(check_scope, scope=scope),
                     resolve=resolve, max_requests=500)
```

## Matching rules

**Allowed domains** match a host *or its subdomains* by default — `example.com`
admits `example.com` and `sub.example.com`. Set `exact_match=True` to admit only
the exact hosts listed; subdomains are then refused unless listed themselves
(use this for targets scoped to specific hosts, not a whole subtree).

**Disallowed domains** are stricter, by design:

| Entry | Blocks |
|---|---|
| `prod.example.com` (bare root) | that exact host only |
| `.prod.example.com` / `*.prod.example.com` | the whole subtree |

So a bare disallowed root can't accidentally reject an in-scope sibling subtree
(`api.stg.example.com` stays allowed when only `prod.example.com` is blocked). To
block a subtree deliberately, prefix the entry with `.` or `*.`.

Matching is case-insensitive and ignores leading/trailing dots.

## Tests

```bash
python3 test_scope_guard.py     # exit 0 = pass
```
