# severity-band

A tiny, dependency-free helper for finding models that accept only a restricted
severity band (`info` / `low` / `medium`) and reserve `high` / `critical` for
human confirmation.

## The problem it prevents

When a detector finds a high- or critical-severity condition and passes that
straight to a finding constructor that rejects it, the constructor raises. If a
broad `except` sits around the construction site — common in scanner code — the
error is swallowed and **the finding is dropped silently**. The most severe
results are exactly the ones that vanish.

## The pattern

Cap the severity into the allowed band, and preserve the true level separately
so the report layer can surface it:

```python
from severity import cap_severity, with_true_severity

finding = Finding(
    severity=cap_severity(raw),                 # high/critical -> medium
    detail=with_true_severity(raw, detail),     # prepends CHAIN_SEVERITY=<raw>
)
```

- `cap_severity(raw)` → `info` / `low` / `medium`. Unknown or empty input maps
  to `medium` (conservative) and never raises.
- `with_true_severity(raw, detail)` → prepends a `CHAIN_SEVERITY=<raw>` marker to
  `detail` only when `raw` is `high` or `critical`; otherwise returns `detail`
  unchanged. The reporting layer reads the marker back to show the real risk.

The band invariant stays in the finding model; this helper only keeps
construction sites from drifting.

## Tests

```bash
python3 test_severity.py     # exit 0 = pass
```
