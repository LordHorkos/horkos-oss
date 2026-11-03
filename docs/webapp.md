# web dashboard

A local, read-only web app over your runs directory — an index of past runs, each
opening the dark KASABONKA dashboard. Stdlib only (`http.server`), no dependency.

## Persist a run, then serve

```python
from horkos_sec import Controller, EvidenceStore, save_run, KASABONKA, TargetProfile

result = Controller(plan, evidence=EvidenceStore("runs/acme"), discover=True).run()
score = KASABONKA().score(TargetProfile(program="acme", scope="focused", ...))
save_run(result, "runs/acme", target_score=score)     # writes runs/acme/run.json
```

```bash
python examples/dashboard_server.py runs        # serves ./runs on 127.0.0.1:8787
# open http://127.0.0.1:8787
```

Or from Python: `from horkos_sec import serve; serve("runs")`.

## Routes

| Route | What |
|---|---|
| `GET /` | index of runs (newest first): program, date, KASABONKA verdict, finding counts |
| `GET /run/<id>` | the dark KASABONKA dashboard for that run, re-rendered from its `run.json` |
| `GET /evidence/<id>/<eid>` | the raw captured response body for a finding, as a text download |

`<id>` is the run's directory name under the runs root.

## Safety

- Binds to **127.0.0.1** by default — a local tool, not an exposed service.
- **Read-only.** It never writes, and re-renders each run from `run.json` on request.
- Run and evidence ids are strictly validated (`[A-Za-z0-9._-]`, no `..`), and the
  resolved evidence path is checked to stay inside the runs root, so a request
  can't path-traverse out.
- Evidence bodies are **raw target responses**, so they're served as
  `text/plain` with `nosniff` and as a download — never as HTML the browser would
  execute. The dashboard HTML itself has every target-supplied value escaped.
- Responses carry a restrictive `Content-Security-Policy`.

## Tests

```bash
python3 tests/test_webapp.py     # or: python -m pytest
```
