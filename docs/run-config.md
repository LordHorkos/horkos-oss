# run-config

Target intake: turn an authorized `Engagement` plus seed URLs into a validated
`RunPlan`. Every seed is authorized before it enters the plan, rejected seeds are
recorded (not silently dropped), and the request rate is held at a safe ceiling
unless you opt out deliberately.

This module only plans — it does not resolve, connect, or scan. The controller
consumes a `RunPlan`.

## Usage

```python
from horkos_sec import Engagement, parse_hackerone_scope, build_run_plan, RunOptions

eng = Engagement("acme", parse_hackerone_scope(pasted).config,
                 authorized=True, modes=("observe",))

plan = build_run_plan(
    eng,
    seeds=["https://example.com/", "https://api.example.com/", "https://evil.test/"],
    options=RunOptions(
        mode="observe",
        rate=0.3,                       # requests/second
        max_requests=500,               # hard lifetime cap
        headers={"X-HackerOne-Research": "your-handle"},
        output_dir="runs/acme",
    ),
)

print(plan.summary())                   # program=acme mode=observe seeds=2 rejected=1 ...
plan.seeds                              # ["https://example.com/", "https://api.example.com/"]
plan.rejected                          # [("https://evil.test/", "out of scope: ...")]
```

## Fail-closed rules

`build_run_plan` raises `ValueError` when:

- the engagement isn't authorized, or the mode isn't one the engagement lists;
- no seed survives authorization (nothing to run);
- `rate` exceeds `PROD_RATE_CEILING` (0.3/s) and `allow_fast_rate` is not set;
- `rate` or `max_requests` is non-positive.

Seeds are de-duplicated; each is authorized with `governance.authorize` (confirmed
engagement + mode + in-scope), so an out-of-scope or unauthorized seed lands in
`plan.rejected` with its reason rather than being scanned.

## RunOptions

`mode`, `rate`, `burst`, `max_requests`, `timeout`, `max_redirects`, `verify_tls`,
`headers` (attribution etc.), `output_dir`, `allow_fast_rate`.

## Tests

```bash
python3 tests/test_run_config.py     # or: python -m pytest
```
