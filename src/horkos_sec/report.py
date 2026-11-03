"""
Report writer — render a run's findings into a HackerOne-style markdown report.

Takes a RunResult (and optionally the EvidenceStore used for the run) and emits
markdown: a header with program/scope/counts, a severity summary, then each
finding sorted by severity with its affected URL, detail, evidence reference, and
a remediation note. write_report() also writes it to a file.

The report states only what the passive detectors observed. It does not claim
exploitation or impact beyond the observation.
"""

from __future__ import annotations

import os
import time
from typing import List, Optional

from .controller import RunResult
from .findings import Finding

_SEV_ORDER = {"medium": 0, "low": 1, "info": 2}

_REMEDIATION = {
    "Missing HSTS header":
        "Send `Strict-Transport-Security` with a long max-age, e.g. "
        "`max-age=63072000; includeSubDomains`.",
    "Missing Content-Security-Policy":
        "Define a `Content-Security-Policy`; start from `default-src 'self'` and tighten.",
    "Missing X-Content-Type-Options: nosniff":
        "Send `X-Content-Type-Options: nosniff` to stop MIME sniffing.",
    "Missing clickjacking protection":
        "Set `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
    "Missing Referrer-Policy":
        "Set `Referrer-Policy`, e.g. `strict-origin-when-cross-origin`.",
    "Cookie without Secure flag":
        "Add the `Secure` attribute so the cookie is only sent over HTTPS.",
    "Cookie without HttpOnly flag":
        "Add `HttpOnly` so the cookie isn't readable from JavaScript.",
    "Cookie without SameSite attribute":
        "Set `SameSite` (`Lax` or `Strict`) to limit cross-site sending.",
}


# CWE + CVSS v3.1 base vector/score per finding title (prefix match for families).
# Scores are deliberately low — these are passive, informational-to-low findings.
_CWE_CVSS = {
    "Missing HSTS header": ("CWE-319", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    "Missing Content-Security-Policy": ("CWE-1021", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3),
    "Missing X-Content-Type-Options: nosniff": ("CWE-693", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    "Missing clickjacking protection": ("CWE-1021", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3),
    "Missing Referrer-Policy": ("CWE-200", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
    "Cookie without Secure flag": ("CWE-614", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
    "Cookie without HttpOnly flag": ("CWE-1004", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 4.3),
    "Cookie without SameSite attribute": ("CWE-1275", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    "CORS allows any origin with credentials": ("CWE-942", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "CORS allows any origin (ACAO: *)": ("CWE-942", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "CORS allows null origin": ("CWE-942", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "Mixed content: http resource on https page": ("CWE-311", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    "Directory listing enabled": ("CWE-548", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "Redirect-like parameter present (unverified)": ("CWE-601", "", 0.0),
    "Weak or invalid X-Frame-Options value": ("CWE-1021", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3),
    "Verbose error / stack trace exposed": ("CWE-209", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "Internal IP address disclosed in body": ("CWE-200", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
    "Sensitive keyword in code comment": ("CWE-615", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "Multiple email addresses exposed": ("CWE-200", "", 0.0),
}

_CWE_CVSS_PREFIX = {
    "Private key exposed": ("CWE-312", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "AWS access key exposed": ("CWE-312", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "Google API key exposed": ("CWE-312", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "GitHub token exposed": ("CWE-312", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "Slack token exposed": ("CWE-312", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "JWT exposed": ("CWE-522", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "Technology/version disclosure": ("CWE-200", "", 0.0),
    "__Secure- cookie": ("CWE-614", "", 0.0),
    "__Host- cookie": ("CWE-614", "", 0.0),
}


def _cwe_cvss(f: Finding):
    if f.title in _CWE_CVSS:
        return _CWE_CVSS[f.title]
    for prefix, val in _CWE_CVSS_PREFIX.items():
        if f.title.startswith(prefix):
            return val
    return ("", "", 0.0)


def _remediation(f: Finding) -> str:
    if f.title in _REMEDIATION:
        return _REMEDIATION[f.title]
    if f.title.startswith("Technology/version disclosure"):
        return "Suppress or genericize the header so software versions aren't revealed."
    return "Review and remediate in line with your security policy."


def _true_severity(f: Finding) -> str:
    # detail may carry a CHAIN_SEVERITY=<raw> marker for findings capped from high/critical
    if f.detail.startswith("CHAIN_SEVERITY="):
        return f.detail.split("=", 1)[1].split(";", 1)[0].strip()
    return f.severity


def _clean_detail(f: Finding) -> str:
    if f.detail.startswith("CHAIN_SEVERITY="):
        parts = f.detail.split(";", 1)
        return parts[1].strip() if len(parts) > 1 else ""
    return f.detail


def build_report(result: RunResult, store=None, title: Optional[str] = None,
                 correlation=None) -> str:
    from .correlation import correlate
    corr = correlation if correlation is not None else correlate(result.findings)

    plan = result.plan
    eng = plan.engagement
    findings = sorted(result.findings,
                      key=lambda f: (_SEV_ORDER.get(f.severity, 3), f.category, f.url, f.title))

    counts = {"medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    L: List[str] = []
    L.append(f"# {title or f'Security findings — {eng.program}'}")
    L.append("")
    L.append(f"- **Program:** {eng.program}")
    L.append(f"- **Date:** {time.strftime('%Y-%m-%d', time.gmtime())}")
    L.append(f"- **Mode:** {plan.options.mode} (passive, observe-only)")
    L.append(f"- **Pages fetched:** {len(result.fetches)}")
    scope_bits = []
    if eng.scope.allowed_domains:
        scope_bits.append("+".join(eng.scope.allowed_domains) + " (and subdomains)")
    if eng.scope.allowed_exact:
        scope_bits.append(", ".join(eng.scope.allowed_exact))
    L.append(f"- **Scope:** {'; '.join(scope_bits) or 'n/a'}")
    if result.aborted:
        L.append(f"- **Note:** run aborted — {result.abort_reason}")
    L.append("")

    # --- Triage: ranked unique issues (the thing to act on) ---
    L.append("## Triage — unique issues")
    L.append("")
    L.append(f"_{corr.summary()}"
             + (f"; {corr.prior_runs} prior run(s) used for stability_ " if corr.prior_runs else "_ ")
             + "")
    L.append("")
    if corr.issues:
        L.append("| # | Conf | Severity | Issue | Pages | CWE · CVSS | Signal |")
        L.append("|---|---|---|---|---|---|---|")
        for i, iss in enumerate(corr.issues, 1):
            sev = iss.severity if iss.true_severity == iss.severity else f"{iss.severity} (rep. {iss.true_severity})"
            cc = f"{iss.cwe}" + (f" · {iss.cvss_score}" if iss.cvss else "")
            sig = "stable" if iss.stable else ("new" if iss.is_new else "")
            L.append(f"| {i} | {iss.confidence:.2f} | {sev} | {iss.title} | "
                     f"{iss.count} | {cc} | {sig} |")
        L.append("")
    else:
        L.append("_No issues cleared the confidence floor "
                 f"({corr.emit_floor:.2f}) — nothing recommended for submission._")
        L.append("")
    if corr.suppressed:
        folded = ", ".join(f"{iss.title} ×{iss.count}" for iss in corr.suppressed[:12])
        more = "" if len(corr.suppressed) <= 12 else f", +{len(corr.suppressed) - 12} more"
        L.append(f"**Suppressed (low confidence, kept for the record):** {folded}{more}.")
        L.append("")

    L.append("## Summary")
    L.append("")
    L.append("| Severity | Count |")
    L.append("|---|---|")
    for sev in ("medium", "low", "info"):
        L.append(f"| {sev} | {counts.get(sev, 0)} |")
    L.append(f"| **total** | **{len(findings)}** |")
    L.append("")

    if not findings:
        L.append("_No findings._")
        return "\n".join(L) + "\n"

    L.append("## Findings")
    L.append("")
    for i, f in enumerate(findings, 1):
        true_sev = _true_severity(f)
        sev_label = f.severity if true_sev == f.severity else f"{f.severity} (reported {true_sev})"
        L.append(f"### {i}. [{sev_label}] {f.title}")
        L.append("")
        L.append(f"- **URL:** {f.url}")
        if f.category:
            L.append(f"- **Category:** {f.category}")
        cwe, cvss, score = _cwe_cvss(f)
        if cwe:
            cvss_bit = f" · CVSS {score} `{cvss}`" if cvss else ""
            L.append(f"- **Weakness:** {cwe}{cvss_bit}")
        detail = _clean_detail(f)
        if detail:
            L.append(f"- **Detail:** {detail}")
        eid = f.evidence.get("evidence_id")
        if eid:
            line = f"- **Evidence:** `{eid}`"
            if store is not None:
                try:
                    meta = store.load(eid)
                    line += f" (HTTP {meta.get('status')}, {meta.get('body_len')} bytes)"
                except OSError:
                    pass
            L.append(line)
        other = {k: v for k, v in f.evidence.items() if k != "evidence_id"}
        if other:
            L.append(f"- **Evidence data:** {other}")
        L.append(f"- **Remediation:** {_remediation(f)}")
        L.append("")

    L.append("---")
    L.append("_Passive observation only; no exploitation was performed. "
             "Findings describe what the server returned to standard GET requests._")
    return "\n".join(L) + "\n"


def write_report(result: RunResult, path: str, store=None, title: Optional[str] = None,
                 correlation=None) -> str:
    md = build_report(result, store=store, title=title, correlation=correlation)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(md)
    return path
