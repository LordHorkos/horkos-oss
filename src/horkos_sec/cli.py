"""
Command-line entry points for server / automation use.

  horkos-scan --config run.json     run one observe-only scan, save the run
  horkos-web  runs [host] [port]    serve the dashboard over a runs directory

A scan config (JSON) names the engagement and, crucially, must set
"authorized": true deliberately — build_run_plan refuses otherwise. The scan is
observe-only: GET/HEAD/OPTIONS, in scope, rate-capped, audited, evidence-backed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from . import (
    Engagement, parse_hackerone_scope, build_run_plan, RunOptions, Controller,
    AuditLog, KillSwitch, EvidenceStore, har_seeds, write_report, write_html_report,
    save_run, KASABONKA, TargetProfile,
)


def _load_scope(cfg) -> "object":
    schemes = cfg.get("allowed_schemes")  # e.g. ["https"] (default) or ["http","https"]
    if cfg.get("scope_text"):
        return parse_hackerone_scope(cfg["scope_text"], allowed_schemes=schemes).config
    if cfg.get("scope_file"):
        with open(cfg["scope_file"], "r", encoding="utf-8") as fh:
            return parse_hackerone_scope(fh.read(), allowed_schemes=schemes).config
    raise SystemExit("config needs scope_text or scope_file")


def scan_main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="horkos-scan", description="Run one observe-only scan.")
    ap.add_argument("--config", required=True, help="path to a JSON scan config")
    ap.add_argument("--allow-private", action="store_true",
                    help="permit loopback/private targets (LAB ONLY)")
    args = ap.parse_args(argv)

    with open(args.config, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)

    program = cfg.get("program") or "program"
    out = cfg.get("out_dir") or f"runs/{program}"
    scope = _load_scope(cfg)

    seeds = list(cfg.get("seeds") or [])
    if cfg.get("har_file") and os.path.exists(cfg["har_file"]):
        with open(cfg["har_file"], "r", encoding="utf-8") as fh:
            seeds += har_seeds(fh.read())
    if not seeds:
        raise SystemExit("config needs at least one seed URL")

    eng = Engagement(program=program, scope=scope,
                     authorized=bool(cfg.get("authorized", False)), modes=("observe",))
    plan = build_run_plan(eng, seeds, RunOptions(
        mode="observe",
        rate=float(cfg.get("rate", 0.3)),
        max_requests=int(cfg.get("max_requests", 200)),
        headers={"X-HackerOne-Research": cfg.get("research_handle", "")} if cfg.get("research_handle") else {},
        output_dir=out,
    ))
    print("plan:", plan.summary())

    key = cfg.get("audit_key")
    audit = AuditLog(f"{out}/audit.jsonl", key=key.encode() if key else None)
    store = EvidenceStore(out)
    kill = KillSwitch(path=f"{out}/STOP")

    result = Controller(plan, audit=audit, kill=kill, evidence=store,
                        discover=True, max_pages=int(cfg.get("max_pages", 50)),
                        max_depth=int(cfg.get("max_depth", 3)),
                        workers=int(cfg.get("workers", 1)),
                        resolve_allow_private=args.allow_private).run()
    print(result.summary())

    score = None
    tp = cfg.get("target_profile")
    if tp:
        score = KASABONKA().score(TargetProfile(program=program, **tp))
        print("KASABONKA:", score.summary())

    write_report(result, f"{out}/report.md", store=store)
    write_html_report(result, f"{out}/dashboard.html", store=store,
                      audit_path=f"{out}/audit.jsonl",
                      audit_key=key.encode() if key else None, target_score=score)
    save_run(result, out, target_score=score)
    ok, bad = AuditLog.verify(f"{out}/audit.jsonl", key=key.encode() if key else None)
    print("audit verified:", ok, "" if ok else f"(broke at line {bad})")
    print(f"outputs in {out}/  (report.md, dashboard.html, run.json, audit.jsonl, evidence/)")
    return 0


def web_main(argv=None) -> int:
    from .webapp import serve
    a = list(sys.argv[1:] if argv is None else argv)
    root = a[0] if a else "runs"
    host = a[1] if len(a) > 1 else "127.0.0.1"
    port = int(a[2]) if len(a) > 2 else 8787
    serve(root, host=host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(scan_main())
