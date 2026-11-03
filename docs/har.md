# har

Pull the endpoints a single-page app only reveals at runtime into the scan —
without an automated browser (roadmap Phase 7, option C).

Export a HAR from your own browser while using the target (DevTools → Network →
"Save all as HAR"). This module reads it and returns the request URLs and
query-parameter names it contains, including the XHR/`fetch` endpoints a static
crawl never sees.

## Usage

```python
from horkos_sec import har_seeds, parse_hackerone_scope, build_run_plan, Engagement, Controller

extra = har_seeds(open("target.har").read())          # URLs captured while browsing
eng = Engagement("acme", parse_hackerone_scope(scope).config, authorized=True, modes=("observe",))

plan = build_run_plan(eng, seeds=["https://example.com/"] + extra)   # HAR URLs are seeds
res = Controller(plan, discover=True).run()
```

`parse_har(data)` (JSON string, bytes, or dict) returns a `HarResult` with
`urls`, `params`, and `methods`. `har_seeds(data)` is the shortcut to just the
URL list.

## Why this design

The URLs are **not fetched here** — they become seeds. `build_run_plan` then
authorizes and scope-filters every one, and the controller fetches them through
the same guarded client (scope, rate, SSRF, audit all apply). So HAR ingestion
widens discovery without a second, ungoverned egress path and without any
dependency — the browser that produced the HAR was yours, not the scanner's.
Out-of-scope URLs in the HAR land in `plan.rejected`, never fetched.

Full automated rendering (a headless browser routed through the guard) is a
later, heavier option; HAR ingestion covers most of the SPA gap with none of the
governance cost.

## Tests

```bash
python3 tests/test_har.py     # or: python -m pytest
```
