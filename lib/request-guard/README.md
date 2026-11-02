# request-guard

A fail-closed pre-flight gate for outbound HTTP requests. Before a request goes
out, it runs four checks in a fixed order and refuses on the first failure:

1. **method** — must be in a non-mutating allowed set (`GET`, `HEAD`, `OPTIONS`)
2. **request cap** — a hard ceiling on total allowed requests
3. **scope** — the URL must be in scope
4. **resolution** — the host must resolve to an address the caller accepts
   (e.g. rejecting private / loopback / link-local, for SSRF safety)

Scope-checking and host resolution are **injected as callables**, so the guard
is independent of any particular scope format or resolver. You bring your own;
two small result protocols (`ScopeResult`, `ResolvedResult`) define what the
guard reads back.

## Usage

```python
from request_guard import RequestGuard

guard = RequestGuard(
    scope_check=my_scope_check,   # (url) -> obj with .in_scope, .reason
    resolve=my_resolve,           # (hostname) -> obj with .is_valid, .denial_reason
    max_requests=500,
)

decision = guard.evaluate("https://target.example/path", method="GET")
if decision.allowed:
    send(...)
else:
    log(decision.reason)          # e.g. "Scope violation: ..." or "IP validation failed: ..."
```

- `evaluate(url, method)` → `GuardDecision(allowed, reasons, resolved)`. Only a
  fully-passing evaluate consumes the request budget; any refusal leaves it
  untouched.
- `is_allowed(url)` → cheap scope-only probe for planning (crawl seeds,
  discovery). Consumes no budget, does no resolution, and **fails closed** if the
  scope check raises.
- `request_count` → requests consumed so far.

## Design notes

- **Order matters and is tested**: cheap/static checks (method, cap) run before
  the ones that touch scope logic and DNS, so a bad request is rejected as early
  and cheaply as possible.
- **Fail closed everywhere**: unknown method, cap reached, out of scope, parse
  error, or resolution failure all return `allowed=False` with a reason; a
  raising scope check in `is_allowed()` returns `False`, never an exception.

## Tests

```bash
python3 test_request_guard.py     # exit 0 = pass
```
