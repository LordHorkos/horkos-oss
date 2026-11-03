# controller

Runs a `RunPlan` accountably. It composes the whole toolkit into one loop:

```
RunPlan  ->  RequestGuard (scope_guard + safe_resolver)
         ->  TokenBucket  (rate + hard cap)
         ->  GuardedHTTPClient (pinned, attributed, recording)
```

and wraps the loop in governance: each seed is **re-authorized at the moment of
use**, the **KillSwitch** is checked before every fetch, and every authorization
decision and request is written to the **AuditLog**.

Observe-only: it issues `GET` against seeds, optionally crawls in-scope links
(`discover=True`), and runs the passive detectors on each response
(`detect=True`, the default), collecting de-duplicated findings. It never mutates
or injects. Active checks are a separate, opt-in layer outside this controller.

## Usage

```python
from horkos_sec import (
    Engagement, parse_hackerone_scope, build_run_plan, RunOptions,
    Controller, AuditLog, KillSwitch,
)

eng = Engagement("acme", parse_hackerone_scope(pasted).config,
                 authorized=True, modes=("observe",))
plan = build_run_plan(eng, seeds=["https://example.com/", "https://api.example.com/"],
                      options=RunOptions(headers={"X-HackerOne-Research": "your-handle"}))

audit = AuditLog("runs/acme/audit.jsonl")
kill = KillSwitch(path="runs/acme/STOP")      # `touch runs/acme/STOP` to abort

result = Controller(plan, audit=audit, kill=kill,
                    discover=True, max_pages=50, max_depth=3).run()
print(result.summary())                       # "acme: 12/12 ok, 7 findings"
for f in result.findings:
    print(f.severity, f.category, f.title, "-", f.url)

ok, _ = AuditLog.verify("runs/acme/audit.jsonl")   # the run is auditable
```

Options: `detect=True` runs passive detectors on each response (findings are
de-duplicated across the whole run by `Finding.key()`); `discover=True` crawls
in-scope links via the same guarded fetch, bounded by `max_pages`/`max_depth`.
Set `detect=False` to fetch without judging.

`workers=N` (default 1) processes distinct hosts concurrently — each worker gets
its own HTTP client and rate bucket (per-host rate), while one shared,
thread-safe guard enforces scope, SSRF, and the **strict** global request cap
across all of them. The kill switch and audit log are shared and thread-safe;
findings are de-duplicated across workers. A single-host run stays sequential.

`resolve_allow_private=True` is for lab targets only — it lets the resolver
admit loopback/private addresses so you can exercise the pipeline against a local
vulnerable app before pointing it at a real program.

## RunResult

`plan`, `fetches` (a `FetchRecord` per URL: `url`, `ok`, `status`, `ip`,
`reason`, `redirects`), `findings` (de-duplicated `Finding`s across the run),
`aborted`, `abort_reason`.

## What it guarantees

- A denied (unauthorized / out-of-scope / mode-mismatch) seed is recorded and
  skipped, never fetched.
- The request budget and rate ceiling from the plan are enforced by the client.
- A tripped kill switch stops the run before the next fetch and is logged.
- With an `AuditLog`, the full sequence — `run_start`, `authorize`/`request` per
  seed, `run_end` — is a verifiable hash chain.

## Tests

```bash
python3 tests/test_controller.py     # or: python -m pytest
```
