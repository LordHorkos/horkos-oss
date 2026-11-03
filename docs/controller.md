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

Observe-only: it issues `GET` against each seed and records the response. It does
not crawl, mutate, or run detectors — those are later layers that consume a
`RunResult`.

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

result = Controller(plan, audit=audit, kill=kill).run()
print(result.summary())                       # "acme: 2/2 ok"
for f in result.fetches:
    print(f.url, f.ok, f.status, f.ip, f.reason)

ok, _ = AuditLog.verify("runs/acme/audit.jsonl")   # the run is auditable
```

`resolve_allow_private=True` is for lab targets only — it lets the resolver
admit loopback/private addresses so you can exercise the pipeline against a local
vulnerable app before pointing it at a real program.

## RunResult

`plan`, `fetches` (a `FetchRecord` per seed: `url`, `ok`, `status`, `ip`,
`reason`, `redirects`), `aborted`, `abort_reason`.

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
