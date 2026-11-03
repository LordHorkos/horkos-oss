# report

Render a run's findings into a HackerOne-style markdown report: a header with
program/scope/counts, a severity summary, then each finding (sorted by severity)
with its affected URL, detail, evidence reference, and remediation.

## Usage

```python
from horkos_sec import Controller, EvidenceStore, build_report, write_report

store = EvidenceStore("runs/acme")
result = Controller(plan, evidence=store, discover=True).run()

md = build_report(result, store=store)        # markdown string
write_report(result, "runs/acme/report.md", store=store)
```

Passing the `EvidenceStore` lets each finding's evidence line include the stored
HTTP status and body size; without it the evidence id alone is shown.

## What it renders

- **Header** — program, date, mode (passive/observe-only), pages fetched, scope,
  and an aborted note if the run was stopped.
- **Summary** — counts by severity (medium / low / info) and a total.
- **Findings** — sorted medium → low → info, each with URL, category, detail,
  evidence id (and status/size when the store is given), any extra evidence data,
  and a remediation note. A finding capped from high/critical shows both the
  stored and the reported severity.
- **Footer** — a statement that this was passive observation only, no
  exploitation.

Remediation text is built in for the passive detector findings (security
headers, cookie flags, info disclosure); anything else gets a generic line.

## Tests

```bash
python3 tests/test_report.py     # or: python -m pytest
```
