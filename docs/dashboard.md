# dashboard (HTML report)

A single self-contained HTML view of a run's findings — the visual counterpart to
the markdown `report`. No server, no dependency, no external resources (no CDN
fonts or scripts), so you can open it straight from disk or hand it over as one
file.

## Usage

```python
from horkos_sec import write_html_report, EvidenceStore

store = EvidenceStore("runs/acme")
write_html_report(result, "runs/acme/dashboard.html", store=store,
                  audit_path="runs/acme/audit.jsonl")   # audit_key=... if keyed
```

`build_html_report(result, ...)` returns the HTML string if you'd rather handle
the file yourself.

## What it shows

- Header: program, date, mode, pages fetched, scope, and an **audit badge**
  (verified / FAILED) when `audit_path` is given.
- Severity summary (medium / low / info / total).
- Findings table, sortable by clicking a column header, severity-colored, with
  title + detail, URL, CWE, CVSS score, category, evidence id (plus HTTP
  status/size when the `EvidenceStore` is passed), and remediation.

## Safety

Findings carry target-controlled text (header values, cookie names, body
snippets, URLs). **Every such value is HTML-escaped** before it enters the page,
so a malicious response cannot turn the dashboard into an XSS. The only script in
the page is a small inline column-sort helper; there are no external references.

## Tests

```bash
python3 tests/test_report_html.py     # or: python -m pytest
```
