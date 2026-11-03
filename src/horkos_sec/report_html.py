"""
Static HTML dashboard for a run — dark "neon filter" theme.

A single self-contained file: no server, no dependency, no external resources
(no CDN fonts/scripts — that would be ironic given the mixed-content detector).
When a KASABONKA TargetScore is passed, the target assessment renders as a
glowing Scope -> Technology -> Hunter-Density -> Result filter chain on top of
the findings.

Everything the target could control (headers, cookie names, body snippets, URLs)
is HTML-escaped before it enters the page, so a malicious response cannot turn
the dashboard into an XSS. The only script in the page is a small inline
column-sort helper.

build_html_report(result, ...) -> str ; write_html_report(result, path, ...) -> path.
"""

from __future__ import annotations

import html
import os
import time
from typing import List, Optional

from .controller import RunResult
from .findings import Finding
from .report import _cwe_cvss, _remediation, _true_severity, _clean_detail, _SEV_ORDER

# Severity accent colors on dark.
_SEV = {"medium": "#f59e0b", "low": "#38bdf8", "info": "#94a3b8"}

_CSS = """
*{box-sizing:border-box}
body{margin:0;padding:32px 28px;background:#070b16;color:#e5ecf5;
 font:14px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
 background-image:linear-gradient(#0b1220 1px,transparent 1px),linear-gradient(90deg,#0b1220 1px,transparent 1px);
 background-size:36px 36px;background-position:center}
.wrap{max-width:1120px;margin:0 auto}
h1{font-size:22px;font-weight:800;letter-spacing:.06em;margin:0 0 4px;text-transform:uppercase}
h2{font-size:13px;font-weight:700;letter-spacing:.18em;text-transform:uppercase;color:#7dd3fc;
 margin:30px 0 12px}
.meta{color:#7e8aa0;font-size:12.5px}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:11.5px;font-weight:700;
 letter-spacing:.04em;border:1px solid}
.ok{color:#4ade80;border-color:#1f7a44;background:rgba(34,197,94,.1)}
.warn{color:#fbbf24;border-color:#7a5a1f;background:rgba(245,158,11,.1)}
.bad{color:#f87171;border-color:#7a2626;background:rgba(239,68,68,.1)}

/* filter chain */
.chain{display:flex;align-items:stretch;gap:0;margin:8px 0 6px;flex-wrap:wrap}
.filter{flex:1 1 180px;min-width:170px;border-radius:14px;padding:18px 16px;position:relative;
 background:linear-gradient(180deg,rgba(255,255,255,.04),rgba(255,255,255,.01));
 border:1px solid var(--c);box-shadow:0 0 22px -6px var(--c),inset 0 0 30px -18px var(--c)}
.filter .lab{font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:#9fb0c7}
.filter .score{font-size:30px;font-weight:800;margin:8px 0 2px;color:var(--c);
 text-shadow:0 0 16px var(--c)}
.filter .tag{font-size:12.5px;color:#cbd5e1;font-weight:600}
.pipe{flex:0 0 26px;align-self:center;height:3px;border-radius:2px;
 background:linear-gradient(90deg,var(--a),var(--b));box-shadow:0 0 10px var(--b)}
.result .v{font-size:20px;font-weight:800;letter-spacing:.04em}
.result .tot{font-size:12px;color:#9fb0c7;margin-top:2px}

table{border-collapse:collapse;width:100%;margin:10px 0 4px;font-size:13px}
th,td{text-align:left;padding:8px 11px;border-bottom:1px solid #182236;vertical-align:top}
th{cursor:pointer;color:#9fb0c7;font-weight:600;font-size:12px;letter-spacing:.03em;
 background:#0c1424;position:sticky;top:0}
th[data-col]:hover{color:#e5ecf5}
tbody tr:hover{background:rgba(125,211,252,.05)}
td.sev{font-weight:700;white-space:nowrap}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;vertical-align:1px;
 box-shadow:0 0 8px currentColor}
code{background:#0e1830;color:#9fd0ff;padding:1px 5px;border-radius:4px;font-size:12px;word-break:break-all}
.sum{width:auto}.sum td,.sum th{border:none;padding:3px 20px 3px 0;background:none;position:static}
.card{background:rgba(255,255,255,.02);border:1px solid #182236;border-radius:12px;padding:14px 16px}
ul.recs{margin:10px 0 0;padding-left:18px;color:#cbd5e1}ul.recs li{margin:3px 0}
footer{color:#5f6b80;font-size:11.5px;margin-top:30px;border-top:1px solid #182236;padding-top:10px}
"""

_SORT_JS = """
document.querySelectorAll('th[data-col]').forEach(function(th){
  th.addEventListener('click',function(){
    var t=th.closest('table'),b=t.tBodies[0],i=+th.dataset.col,
        rows=[].slice.call(b.rows),asc=th.dataset.asc!=='1';
    rows.sort(function(x,y){return (x.cells[i].dataset.k||x.cells[i].innerText)
      .localeCompare((y.cells[i].dataset.k||y.cells[i].innerText),undefined,{numeric:true})*(asc?1:-1);});
    th.dataset.asc=asc?'1':'0';rows.forEach(function(r){b.appendChild(r);});
  });
});
"""

_VERDICT = {"commit": ("ok", "#4ade80"), "learn": ("warn", "#fbbf24"), "drop": ("bad", "#f87171")}


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _filter_card(label, score, color, tag):
    return (f'<div class="filter" style="--c:{color}">'
            f'<div class="lab">{_esc(label)}</div>'
            f'<div class="score">{score}<span style="font-size:14px;color:#64748b">/5</span></div>'
            f'<div class="tag">{_esc(tag)}</div></div>')


def _tag_for(name, s):
    scale = {
        "scope_size": ("Focused scope", "Moderate scope", "Wide / wildcard"),
        "tech_familiarity": ("Understandable stack", "Mixed familiarity", "Unfamiliar stack"),
        "hunter_density": ("Low competition", "Some competition", "Crowded"),
    }[name]
    return scale[0] if s >= 4 else scale[1] if s == 3 else scale[2]


def _kasabonka_panel(score) -> str:
    sc = score.factors["scope_size"][0]
    te = score.factors["tech_familiarity"][0]
    de = score.factors["hunter_density"][0]
    vcls, vcol = _VERDICT.get(score.verdict, ("warn", "#fbbf24"))

    chain = (
        '<div class="chain">'
        + _filter_card("Scope Definition", sc, "#22d3ee", _tag_for("scope_size", sc))
        + '<div class="pipe" style="--a:#22d3ee;--b:#3b82f6"></div>'
        + _filter_card("Technology Stack", te, "#3b82f6", _tag_for("tech_familiarity", te))
        + '<div class="pipe" style="--a:#3b82f6;--b:#f59e0b"></div>'
        + _filter_card("Hunter Density", de, "#f59e0b", _tag_for("hunter_density", de))
        + '<div class="pipe" style="--a:#f59e0b;--b:' + vcol + '"></div>'
        + f'<div class="filter result" style="--c:{vcol}">'
          f'<div class="lab">Result</div>'
          f'<div class="v" style="color:{vcol};text-shadow:0 0 16px {vcol}">{_esc(score.verdict.upper())}</div>'
          f'<div class="tot">{score.total} / 30</div></div>'
        + '</div>')

    rows = []
    for name, (s, mx, note) in score.factors.items():
        rows.append(f'<tr><td>{_esc(name.replace("_", " "))}</td><td>{s} / {mx}</td>'
                    f'<td class="meta">{_esc(note)}</td></tr>')
    recs = "".join(f"<li>{_esc(r)}</li>" for r in score.recommendations)

    return (
        '<h2>KASABONKA — target assessment</h2>'
        f'<div class="meta" style="margin-bottom:10px"><b style="color:#e5ecf5">{_esc(score.program or "target")}</b> '
        f'· <span class="badge {vcls}">{_esc(score.verdict.upper())} — {score.total}/30</span></div>'
        + chain +
        '<div class="card" style="margin-top:14px">'
        '<table class="sum"><thead><tr><th>Factor</th><th>Score</th><th>Why</th></tr></thead><tbody>'
        + "".join(rows) +
        f'<tr><td><b>Total</b></td><td><b>{score.total} / 30</b></td><td></td></tr></tbody></table>'
        f'<ul class="recs">{recs}</ul></div>')


def _triage_panel(corr) -> str:
    h = ['<h2>Triage — unique issues</h2>']
    h.append(f'<div class="meta" style="margin-bottom:8px">{_esc(corr.summary())}'
             + (f' · {corr.prior_runs} prior run(s) used for stability' if corr.prior_runs else '')
             + '</div>')
    if not corr.issues:
        h.append('<p class="meta"><i>No issue cleared the confidence floor '
                 f'({corr.emit_floor:.2f}) — nothing recommended for submission.</i></p>')
    else:
        h.append('<table><thead><tr>'
                 '<th data-col="0">Conf</th><th data-col="1">Severity</th>'
                 '<th data-col="2">Issue</th><th data-col="3">Pages</th>'
                 '<th data-col="4">CWE</th><th data-col="5">CVSS</th>'
                 '<th data-col="6">Signal</th></tr></thead><tbody>')
        for iss in corr.issues:
            col = _SEV.get(iss.severity, "#94a3b8")
            sev_txt = (iss.severity if iss.true_severity == iss.severity
                       else f"{iss.severity} (rep. {iss.true_severity})")
            if iss.stable:
                sig = '<span class="badge ok">stable</span>'
            elif iss.is_new:
                sig = '<span class="badge warn">new</span>'
            else:
                sig = ''
            # confidence as a 0..99 integer key so the column sorts numerically
            ckey = int(round(iss.confidence * 100))
            h.append(
                f'<tr>'
                f'<td data-k="{ckey}" style="font-weight:700;color:{col}">{iss.confidence:.2f}</td>'
                f'<td class="sev" style="color:{col}">'
                f'<span class="dot" style="color:{col}"></span>{_esc(sev_txt)}</td>'
                f'<td>{_esc(iss.title)}'
                + (f'<br><span class="meta">{_esc(iss.detail)}</span>' if iss.detail else '')
                + '</td>'
                f'<td data-k="{iss.count}">{iss.count}</td>'
                f'<td>{_esc(iss.cwe)}</td>'
                f'<td>{_esc(iss.cvss_score) if iss.cvss else ""}</td>'
                f'<td>{sig}</td></tr>')
        h.append('</tbody></table>')
    if corr.suppressed:
        folded = ", ".join(f"{_esc(i.title)} ×{i.count}" for i in corr.suppressed[:12])
        more = "" if len(corr.suppressed) <= 12 else f", +{len(corr.suppressed) - 12} more"
        h.append(f'<div class="meta" style="margin-top:8px"><b>Suppressed</b> '
                 f'(low confidence, kept): {folded}{more}.</div>')
    return "".join(h)


def build_html_report(result: RunResult, store=None, title: Optional[str] = None,
                      audit_path: Optional[str] = None, audit_key: Optional[bytes] = None,
                      target_score=None, correlation=None) -> str:
    from .correlation import correlate
    corr = correlation if correlation is not None else correlate(result.findings)

    plan = result.plan
    eng = plan.engagement
    findings: List[Finding] = sorted(
        result.findings,
        key=lambda f: (_SEV_ORDER.get(f.severity, 3), f.category, f.url, f.title))

    counts = {"medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    audit_badge = ""
    if audit_path:
        from .governance import AuditLog
        ok = AuditLog.verify(audit_path, key=audit_key)[0]
        audit_badge = (f' · <span class="badge {"ok" if ok else "bad"}">'
                       f'audit {"verified" if ok else "FAILED"}</span>')

    h = ['<!doctype html><html><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         f'<title>{_esc(title or f"Findings — {eng.program}")}</title>',
         f'<style>{_CSS}</style></head><body><div class="wrap">']
    h.append(f'<h1>{_esc(title or f"Security findings — {eng.program}")}</h1>')
    scope_bits = []
    if eng.scope.allowed_domains:
        scope_bits.append("+".join(eng.scope.allowed_domains) + " (+subdomains)")
    if eng.scope.allowed_exact:
        scope_bits.append(", ".join(eng.scope.allowed_exact))
    h.append('<div class="meta">'
             f'Program <b style="color:#e5ecf5">{_esc(eng.program)}</b> · '
             f'{time.strftime("%Y-%m-%d", time.gmtime())} · mode {_esc(plan.options.mode)} (observe-only) · '
             f'{len(result.fetches)} pages · scope: {_esc("; ".join(scope_bits) or "n/a")}'
             f'{audit_badge}'
             + (' · <b style="color:#f87171">run aborted</b>' if result.aborted else '') + '</div>')

    if target_score is not None:
        h.append(_kasabonka_panel(target_score))

    h.append(_triage_panel(corr))

    h.append('<h2>All observations (raw)</h2>')
    h.append('<table class="sum"><tr><th>medium</th><th>low</th><th>info</th><th>total</th></tr>'
             f'<tr><td>{counts["medium"]}</td><td>{counts["low"]}</td>'
             f'<td>{counts["info"]}</td><td><b>{len(findings)}</b></td></tr></table>')

    if not findings:
        h.append('<p><i>No findings.</i></p>')
    else:
        h.append('<table><thead><tr>'
                 '<th data-col="0">Severity</th><th data-col="1">Title</th>'
                 '<th data-col="2">URL</th><th data-col="3">CWE</th>'
                 '<th data-col="4">CVSS</th><th data-col="5">Category</th>'
                 '<th data-col="6">Evidence</th><th>Remediation</th>'
                 '</tr></thead><tbody>')
        rank = {"medium": 0, "low": 1, "info": 2}
        for f in findings:
            cwe, cvss, score_v = _cwe_cvss(f)
            true_sev = _true_severity(f)
            sev_txt = f.severity if true_sev == f.severity else f"{f.severity} (rep. {true_sev})"
            col = _SEV.get(f.severity, "#94a3b8")
            eid = f.evidence.get("evidence_id", "")
            ev = f"<code>{_esc(eid)}</code>" if eid else ""
            if eid and store is not None:
                try:
                    m = store.load(eid)
                    ev += f' <span class="meta">{_esc(m.get("status"))}·{_esc(m.get("body_len"))}b</span>'
                except OSError:
                    pass
            detail = _clean_detail(f)
            title_cell = _esc(f.title) + (f'<br><span class="meta">{_esc(detail)}</span>' if detail else "")
            h.append(
                f'<tr>'
                f'<td class="sev" data-k="{rank.get(f.severity,3)}" style="color:{col}">'
                f'<span class="dot" style="color:{col}"></span>{_esc(sev_txt)}</td>'
                f'<td>{title_cell}</td>'
                f'<td><code>{_esc(f.url)}</code></td>'
                f'<td>{_esc(cwe)}</td><td>{_esc(score_v) if cvss else ""}</td>'
                f'<td>{_esc(f.category)}</td><td>{ev}</td>'
                f'<td class="meta">{_esc(_remediation(f))}</td></tr>')
        h.append('</tbody></table>')

    h.append('<footer>Passive observation only; no exploitation was performed. '
             'All target-supplied text on this page is HTML-escaped.</footer>')
    h.append(f'</div><script>{_SORT_JS}</script></body></html>')
    return "".join(h)


def write_html_report(result: RunResult, path: str, store=None, title: Optional[str] = None,
                      audit_path: Optional[str] = None, audit_key: Optional[bytes] = None,
                      target_score=None, correlation=None) -> str:
    htmls = build_html_report(result, store=store, title=title,
                              audit_path=audit_path, audit_key=audit_key,
                              target_score=target_score, correlation=correlation)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(htmls)
    return path
