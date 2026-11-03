# evidence

Persist the request/response behind each finding so it can be reproduced and
reviewed. Each saved response is two files under `<output_dir>/evidence/`:

- `<id>.json` — metadata: url, final_url, status, ip, the request (method +
  headers sent), response headers, body length, a SHA-256 of the body,
  truncation flag, timestamp.
- `<id>.body` — the raw response bytes.

`id` is content-addressed (SHA-256 over final_url + body), so capturing the same
page twice stores it once and findings cite a stable id.

## Usage

Usually via the controller — pass an `output_dir` in `RunOptions`, or an
`EvidenceStore` directly, and findings come back tagged:

```python
from horkos_sec import Controller, EvidenceStore

store = EvidenceStore("runs/acme")
result = Controller(plan, evidence=store, discover=True).run()

for f in result.findings:
    eid = f.evidence["evidence_id"]
    assert store.verify(eid)              # stored body matches its recorded hash
    meta = store.load(eid)                # url, status, headers, ...
```

If `plan.options.output_dir` is set, the controller creates the store itself.

## Direct use

```python
store = EvidenceStore("runs/acme")
eid = store.save_response(fetch_result, request_headers={"X-HackerOne-Research": "horkos"})
store.load(eid)            # metadata dict
store.body_path(eid)       # path to the raw body
store.verify(eid)          # re-hash the body and compare to metadata
```

`verify()` re-hashes the stored body and compares it to the recorded
`body_sha256`, so an altered evidence file is detectable.

## Tests

```bash
python3 tests/test_evidence.py     # or: python -m pytest
```
