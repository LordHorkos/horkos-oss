"""Severity banding — keep finding-construction sites from throwing on a
Finding model that only accepts a restricted severity band.

Some finding models hard-cap `severity` to {info, low, medium} and reserve
high/critical for human confirmation. A construction site that detects a
high/critical condition must cap the severity into the allowed band and record
the TRUE severity separately (here, via a CHAIN_SEVERITY marker in the finding's
detail field, which the reporting layer can read back to surface the real risk).
It must NOT pass high/critical straight to the model's constructor: if that
raises, a surrounding broad `except` can swallow the error and silently drop the
finding entirely.

Centralizing the mapping here keeps construction sites from drifting. The band
invariant itself lives in the finding model and is not loosened by this helper.
"""

# high/critical fold DOWN into the allowed band; the true level is preserved
# separately by with_true_severity() in the detail field.
_CAP = {
    "info": "info", "low": "low", "medium": "medium",
    "high": "medium", "critical": "medium",
}


def cap_severity(raw: str) -> str:
    """Map a raw severity into the allowed {info,low,medium} band;
    high/critical -> medium. Unknown/empty -> medium (conservative, never
    raises)."""
    return _CAP.get((raw or "").lower(), "medium")


def with_true_severity(raw: str, detail: str = "") -> str:
    """Return `detail` prefixed with a CHAIN_SEVERITY=<raw> marker when `raw`
    exceeds the cap (high/critical), so the true severity survives into the
    report layer. When `raw` is already within band, `detail` is returned
    unchanged (no marker noise)."""
    r = (raw or "").lower()
    if r in ("high", "critical"):
        marker = f"CHAIN_SEVERITY={r}"
        return f"{marker}; {detail}" if detail else marker
    return detail
