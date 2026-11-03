#!/usr/bin/env python3
"""
First live observe-only run against an authorized HackerOne program.

Fill in the scope and seeds, confirm authorization, then run. This issues only
GET/HEAD/OPTIONS, stays in scope, rate-limits, records evidence, writes a
tamper-evident audit log, and is stoppable via the STOP file. See LAUNCH.md for
the per-engagement go/no-go before you run this against a real program.

    pip install -e .
    python examples/live_observe_run.py
"""
import os
from horkos_sec import (
    Engagement, parse_hackerone_scope, build_run_plan, RunOptions,
    Controller, AuditLog, KillSwitch, EvidenceStore, har_seeds,
    write_report, write_html_report, save_run,
)

# ------------------------------------------------------------------ CONFIGURE
PROGRAM = "acme"                         # the program handle
RESEARCH_HANDLE = "horkos"               # your HackerOne handle (attribution)
OUT = f"runs/{PROGRAM}"

# Paste the program's scope here (JSON from the API, or the copied scope table):
SCOPE_TEXT = """
In scope
WILDCARD	*.example.com
URL	api.example.com
Out of scope
URL	legacy.example.com
"""

# Start small for the first run: one seed, few pages.
SEEDS = ["https://www.example.com/"]

# Optional: endpoints from a HAR you exported while browsing the target.
HAR_FILE = None                          # e.g. "target.har"
# ---------------------------------------------------------------------------

scope = parse_hackerone_scope(SCOPE_TEXT).config

seeds = list(SEEDS)
if HAR_FILE and os.path.exists(HAR_FILE):
    seeds += har_seeds(open(HAR_FILE).read())

eng = Engagement(
    program=PROGRAM,
    scope=scope,
    authorized=True,                     # set True ONLY after confirming the program
    modes=("observe",),
)

plan = build_run_plan(eng, seeds, RunOptions(
    mode="observe",
    rate=0.3,                            # <= 0.3 req/s for a real target
    max_requests=200,                    # hard ceiling for the run
    headers={"X-HackerOne-Research": RESEARCH_HANDLE},
    output_dir=OUT,
))
print("Plan:", plan.summary())
for url, why in plan.rejected:
    print("  rejected:", url, "-", why)

kill = KillSwitch(path=f"{OUT}/STOP")    # `touch runs/acme/STOP` to abort
audit = AuditLog(f"{OUT}/audit.jsonl")   # add key=b"..." for a tamper-resistant log
store = EvidenceStore(OUT)

result = Controller(plan, audit=audit, kill=kill, evidence=store,
                    discover=True, max_pages=5, max_depth=2).run()

print(result.summary())
write_report(result, f"{OUT}/report.md", store=store)
write_html_report(result, f"{OUT}/dashboard.html", store=store, audit_path=f"{OUT}/audit.jsonl")
save_run(result, OUT)                     # makes the run show up in the web dashboard
ok, bad = AuditLog.verify(f"{OUT}/audit.jsonl")
print("audit verified:", ok, "" if ok else f"(broke at line {bad})")
print(f"report: {OUT}/report.md   dashboard: {OUT}/dashboard.html")
print(f"web dashboard: python examples/dashboard_server.py runs   (then open http://127.0.0.1:8787)")
