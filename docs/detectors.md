# detectors

Passive detectors judge what a normal `GET` returned — no injection, no
mutation, no extra requests. Each reads a response (status, headers, body) and
emits `Finding`s.

## What they check

| Detector | Flags |
|---|---|
| `detect_security_headers` | missing HSTS (HTTPS only), CSP, `X-Content-Type-Options: nosniff`, clickjacking protection (XFO or CSP `frame-ancestors`), `Referrer-Policy` |
| `detect_cookies` | `Set-Cookie` without `Secure` (HTTPS), `HttpOnly`, or `SameSite` |
| `detect_info_disclosure` | `Server` / `X-Powered-By` / version-revealing headers |

## Usage

```python
from horkos_sec import run_passive_detectors

# `result` is a FetchResult (or anything with .url/.final_url, .status, .headers, .body)
findings = run_passive_detectors(result)
for f in findings:
    print(f.severity, f.category, f.title, "-", f.url)
```

Each `Finding` has `title` (stable, used for de-dup), `severity` (capped to
info/low/medium), `url`, `category`, `detail`, and `evidence`. Construct your own
with `make_finding(title, raw_severity, url, ...)` — it caps the severity and
preserves the true level in `detail` via a CHAIN_SEVERITY marker when it exceeds
the band.

## Cookies and repeated headers

A response can carry several `Set-Cookie` headers, but a flat header dict keeps
only the last. Pass the raw values explicitly when you have them:

```python
run_passive_detectors(result, set_cookies=["a=1; Secure", "b=2"])
```

Without `set_cookies`, the detector falls back to the single `set-cookie` in the
header dict.

## Scope

These are **passive only**. Active checks — parameter injection, auth/IDOR
probing, anything that sends crafted input — are a separate, opt-in layer and are
not part of this module.

## Tests

```bash
python3 tests/test_detectors.py     # or: python -m pytest
```
