"""
Static HTML dashboard for a run's findings — a single self-contained file.

No server, no dependency, no external resources (no CDN fonts/scripts — that would
be ironic given the mixed-content detector). Everything the target could control
(headers, cookie names, body snippets, URLs) is HTML-escaped before it goes in the
page, so a malicious response can't turn the dashboard itself into an XSS.

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

_SEV_COLOR = {"medium": "#f9eeda", "low": "#e7f1fb", "info": "#f0efec"}

_CSS = """
:root{color-scheme:light dark}
body{font:14px/1.5 system-ui,sans-serif;margin:0;padding:24px;max-width:1100px}
h1{font-size:20px;margin:0 0 4px}
.meta{color:#666;font-size:13px;margin-bottom:16px}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}
.ok{background:#e5f4e4;color:#1a5c1a}.bad{background:#fbebeb;color:#8a1a1a}
table{border-collapse:collapse;width:100%;margin:12px 0}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #ddd;vertical-align:top}
th{cursor:pointer;background:#f5f5f5;position:sticky;top:0}
td.sev{font-weight:600;white-space:nowrap}
code{background:#f0efec;padding:1px 4px;border-radius:3px;font-size:12px;word-break:break-all}
.sum td,.sum th{border:none;padding:2px 14px 2px 0}
footer{color:#888;font-size:12px;margin-top:24px;border-top:1px solid #ddd;padding-top:8px}
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


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def build_html_report(result: RunResult, store=None, title: Optional[str] = None,
                      audit_path: Optional[str] = None, audit_key: Optional[bytes] = None) -> str:
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
        audit_badge = (f'<span class="badge {"ok" if ok else "bad"}">'
                       f'audit {"verified" if ok else "FAILED"}</span>')

    h = [f'<!doctype html><html><head><meta charset="utf-8">',
         f'<meta name="viewport" content="width=device-width,initial-scale=1">',
         f'<title>{_esc(title or f"Findings — {eng.program}")}</title>',
         f'<style>{_CSS}</style></head><body>']
    h.append(f'<h1>{_esc(title or f"Security findings — {eng.program}")}</h1>')
    scope_bits = []
    if eng.scope.allowed_domains:
        scope_bits.append("+".join(eng.scope.allowed_domains) + " (+subdomains)")
    if eng.scope.allowed_exact:
        scope_bits.append(", ".join(eng.scope.allowed_exact))
    h.append('<div class="meta">'
             f'Program <b>{_esc(eng.program)}</b> · {time.strftime("%Y-%m-%d", time.gmtime())} · '
             f'mode {_esc(plan.options.mode)} (observe-only) · '
             f'{len(result.fetches)} pages · scope: {_esc("; ".join(scope_bits) or "n/a")} '
             f'{audit_badge}'
             + (' · <b>run aborted</b>' if result.aborted else '') + '</div>')

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
            cwe, cvss, score = _cwe_cvss(f)
            true_sev = _true_severity(f)
            sev_txt = f.severity if true_sev == f.severity else f"{f.severity} (rep. {true_sev})"
            color = _SEV_COLOR.get(f.severity, "#fff")
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
                f'<tr style="background:{color}">'
                f'<td class="sev" data-k="{rank.get(f.severity,3)}">{_esc(sev_txt)}</td>'
                f'<td>{title_cell}</td>'
                f'<td><code>{_esc(f.url)}</code></td>'
                f'<td>{_esc(cwe)}</td><td>{_esc(score) if cvss else ""}</td>'
                f'<td>{_esc(f.category)}</td><td>{ev}</td>'
                f'<td>{_esc(_remediation(f))}</td></tr>')
        h.append('</tbody></table>')

    h.append('<footer>Passive observation only; no exploitation was performed. '
             'All target-supplied text on this page is HTML-escaped.</footer>')
    h.append(f'<script>{_SORT_JS}</script></body></html>')
    return "".join(h)


def write_html_report(result: RunResult, path: str, store=None, title: Optional[str] = None,
                      audit_path: Optional[str] = None, audit_key: Optional[bytes] = None) -> str:
    htmls = build_html_report(result, store=store, title=title,
                              audit_path=audit_path, audit_key=audit_key)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(htmls)
    return path
