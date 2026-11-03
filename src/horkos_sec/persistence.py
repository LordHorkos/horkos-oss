"""
Run persistence — save a finished run as machine-readable JSON so the web app
can list and re-render it later, and rebuild a RunResult from that JSON.

A run directory (the run's output_dir) ends up with:
  run.json        this module's manifest (program, findings, KASABONKA score, ...)
  audit.jsonl     the audit chain (governance)
  evidence/       captured responses (evidence)
  report.md / dashboard.html   optional rendered outputs

No new dependency — just json.
"""

from __future__ import annotations

import html as _html
import json
import os
import time
from typing import Dict, List, Optional

from .controller import RunResult, FetchRecord
from .findings import Finding
from .governance import Engagement
from .kasabonka import TargetScore
from .run_config import RunPlan, RunOptions
from .scope_guard import ScopeConfig


def run_to_dict(result: RunResult, target_score: Optional[TargetScore] = None) -> Dict:
    plan = result.plan
    eng = plan.engagement
    return {
        "program": eng.program,
        "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": plan.options.mode,
        "aborted": result.aborted,
        "abort_reason": result.abort_reason,
        "pages": len(result.fetches),
        "scope": {
            "allowed_domains": list(eng.scope.allowed_domains),
            "allowed_exact": list(eng.scope.allowed_exact),
        },
        "findings": [
            {"title": f.title, "severity": f.severity, "url": f.url,
             "category": f.category, "detail": f.detail, "evidence": dict(f.evidence)}
            for f in result.findings
        ],
        "target_score": None if target_score is None else {
            "program": target_score.program,
            "total": target_score.total,
            "verdict": target_score.verdict,
            "factors": {k: list(v) for k, v in target_score.factors.items()},
            "recommendations": list(target_score.recommendations),
        },
    }


def save_run(result: RunResult, out_dir: str, target_score: Optional[TargetScore] = None) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "run.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(run_to_dict(result, target_score), fh, indent=2, sort_keys=True)
    return path


def load_run(out_dir: str) -> Dict:
    with open(os.path.join(out_dir, "run.json"), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _rebuild(data: Dict):
    sc = data.get("scope") or {}
    dom = list(sc.get("allowed_domains") or [])
    exact = list(sc.get("allowed_exact") or [])
    if not dom and not exact:
        exact = ["(unknown)"]
    eng = Engagement(data.get("program", ""),
                     ScopeConfig(allowed_domains=dom, allowed_exact=exact,
                                 allowed_schemes=["https"]),
                     authorized=True, modes=("observe",))
    plan = RunPlan(engagement=eng, seeds=[], options=RunOptions(mode=data.get("mode", "observe")))
    result = RunResult(plan=plan)
    result.fetches = [FetchRecord("", True, 200) for _ in range(int(data.get("pages", 0)))]
    result.findings = [
        Finding(title=f.get("title", ""), severity=f.get("severity", "info"),
                url=f.get("url", ""), category=f.get("category", ""),
                detail=f.get("detail", ""), evidence=dict(f.get("evidence") or {}))
        for f in data.get("findings", [])
    ]
    result.aborted = bool(data.get("aborted"))
    result.abort_reason = data.get("abort_reason", "")

    ts = data.get("target_score")
    score = None
    if ts:
        score = TargetScore(
            program=ts.get("program", eng.program),
            factors={k: tuple(v) for k, v in (ts.get("factors") or {}).items()},
            total=ts.get("total", 0),
            verdict=ts.get("verdict", "learn"),
            recommendations=list(ts.get("recommendations") or []),
        )
    return result, score


def render_run_html(data: Dict, store=None) -> str:
    """Rebuild a RunResult from a run.json dict and render the dashboard HTML."""
    from .report_html import build_html_report
    result, score = _rebuild(data)
    return build_html_report(result, store=store, target_score=score,
                             title=f"{data.get('program','')} — {data.get('date','')[:10]}")


def list_runs(root: str) -> List[Dict]:
    """Scan `root` for run directories (those containing run.json), newest first.
    Each entry: {id, program, date, verdict, total, counts{...}, pages, aborted}."""
    out: List[Dict] = []
    if not os.path.isdir(root):
        return out
    for name in sorted(os.listdir(root)):
        rj = os.path.join(root, name, "run.json")
        if not os.path.isfile(rj):
            continue
        try:
            with open(rj, "r", encoding="utf-8") as fh:
                d = json.load(fh)
        except (ValueError, OSError):
            continue
        counts = {"medium": 0, "low": 0, "info": 0}
        for f in d.get("findings", []):
            counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
        ts = d.get("target_score") or {}
        out.append({
            "id": name, "program": d.get("program", name), "date": d.get("date", ""),
            "verdict": ts.get("verdict", ""), "total": ts.get("total", ""),
            "counts": counts, "pages": d.get("pages", 0), "aborted": bool(d.get("aborted")),
        })
    out.sort(key=lambda r: r["date"], reverse=True)
    return out


_VBADGE = {"commit": "ok", "learn": "warn", "drop": "bad", "": ""}

_INDEX_CSS = """
body{margin:0;padding:32px 28px;background:#070b16;color:#e5ecf5;
 font:14px/1.5 ui-sans-serif,system-ui,sans-serif;
 background-image:linear-gradient(#0b1220 1px,transparent 1px),linear-gradient(90deg,#0b1220 1px,transparent 1px);
 background-size:36px 36px}
.wrap{max-width:1000px;margin:0 auto}
h1{font-size:22px;font-weight:800;letter-spacing:.06em;text-transform:uppercase}
a{color:#7dd3fc;text-decoration:none}a:hover{text-decoration:underline}
table{border-collapse:collapse;width:100%;margin-top:14px;font-size:13px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid #182236}
th{color:#9fb0c7;font-size:12px}
tr:hover td{background:rgba(125,211,252,.05)}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;border:1px solid}
.ok{color:#4ade80;border-color:#1f7a44}.warn{color:#fbbf24;border-color:#7a5a1f}.bad{color:#f87171;border-color:#7a2626}
.meta{color:#7e8aa0;font-size:12px}
"""


def build_index_html(runs: List[Dict]) -> str:
    rows = []
    for r in runs:
        rid = _html.escape(r["id"])
        vb = _VBADGE.get(r["verdict"], "")
        verdict = (f'<span class="badge {vb}">{_html.escape(r["verdict"].upper())} '
                   f'{r["total"]}/30</span>') if r["verdict"] else '<span class="meta">—</span>'
        c = r["counts"]
        rows.append(
            f'<tr><td><a href="/run/{rid}">{_html.escape(r["program"])}</a>'
            + (' <span class="badge bad">aborted</span>' if r["aborted"] else '') + '</td>'
            f'<td class="meta">{_html.escape(r["date"][:16].replace("T"," "))}</td>'
            f'<td>{verdict}</td>'
            f'<td class="meta">{c["medium"]}m / {c["low"]}l / {c["info"]}i</td>'
            f'<td class="meta">{r["pages"]}</td></tr>')
    body = ("".join(rows) if rows
            else '<tr><td colspan="5" class="meta">No runs yet.</td></tr>')
    return (f'<!doctype html><html><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>horkos-oss runs</title><style>{_INDEX_CSS}</style></head><body><div class="wrap">'
            f'<h1>horkos-oss — runs</h1>'
            f'<table><thead><tr><th>Program</th><th>Date</th><th>Target</th>'
            f'<th>Findings</th><th>Pages</th></tr></thead><tbody>{body}</tbody></table>'
            f'</div></body></html>')
