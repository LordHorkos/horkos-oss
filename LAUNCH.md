# Launch checklist — observe-only finder

`horkos_sec` composes into an observe-only bug finder. "Launch" means pointing it
at a real, authorized program. This checklist is the go/no-go for each engagement.
Every box is enforced in code where marked; the rest are your responsibility.

## Build status

All pipeline modules are present and tested end-to-end against a deliberately
vulnerable loopback target (`tests/test_e2e_labrat.py`): authorize → crawl →
passive detect → evidence → audit → report.

- [x] Guarded, IP-pinned, attributed HTTP client — `http_client`
- [x] Scope ingestion from HackerOne — `hackerone_scope`, `scope_guard`
- [x] SSRF-safe resolution — `safe_resolver`
- [x] Per-request gate + rate limit — `request_guard`, `rate_limiter`
- [x] Target intake with a safe rate ceiling — `run_config`
- [x] Authorization gate, audit log, kill switch — `governance`
- [x] Passive discovery (scope-gated crawl) — `discovery`
- [x] Passive detectors + finding model — `detectors`, `findings`
- [x] Controller wiring it all, observe-only — `controller`
- [x] Reproducible evidence — `evidence`
- [x] Report writer — `report`
- [x] End-to-end validation against a lab rat — `tests/test_e2e_labrat.py`

## Per-engagement go/no-go

Before a live run:

1. **Authorization (code-enforced).** The program is a real, authorized
   engagement. Set `Engagement(authorized=True)` only after you have confirmed
   it; `authorize()` refuses otherwise, and the controller re-authorizes every
   URL at the moment of use.
2. **Scope loaded (code-enforced).** Build the `ScopeConfig` from the program's
   own scope via `parse_hackerone_scope`. Out-of-scope URLs are refused and
   crawling never leaves scope.
3. **Rate ceiling (code-enforced).** Keep `RunOptions.rate` ≤ 0.3/s;
   `build_run_plan` refuses higher without an explicit `allow_fast_rate`.
4. **Mode (code-enforced).** Keep `mode="observe"`. Active modes are not
   implemented here and must not be improvised.
5. **Audit on.** Pass an `AuditLog`; confirm `AuditLog.verify()` after the run.
6. **Kill switch ready.** Pass a `KillSwitch(path=...)`; know the sentinel path
   so you (or a program complaint) can stop the run instantly.
7. **Evidence on.** Set `output_dir` (or pass an `EvidenceStore`) so findings are
   reproducible.
8. **Attribution.** Set the program's required research header in
   `RunOptions.headers`.
9. **TLS verification on.** Leave `verify_tls=True` for real targets.
10. **Program terms (your responsibility).** Re-read the program's policy, rules
    of engagement, and disclosure terms. Confirm automated scanning is permitted
    and within any stated rate/volume limits.

## Hard lines (not in this toolkit)

- **No active testing.** This finder only issues GET/HEAD/OPTIONS and judges what
  comes back. Parameter injection, auth/IDOR probing, or anything that sends
  crafted input is out of scope here and must not be bolted on without a
  deliberate, separately reviewed active layer and its own gates.
- **No autonomous fire loop.** There is no component that decides on its own to
  attack. A run does exactly what the plan authorizes.

## Minimal live invocation

```python
from functools import partial
from horkos_sec import (
    Engagement, parse_hackerone_scope, build_run_plan, RunOptions,
    Controller, AuditLog, KillSwitch, EvidenceStore, write_report,
)

eng = Engagement("acme", parse_hackerone_scope(pasted_scope).config,
                 authorized=True, modes=("observe",))     # authorized set deliberately
plan = build_run_plan(eng, seeds, RunOptions(
    mode="observe", rate=0.3,
    headers={"X-HackerOne-Research": "horkos"}, output_dir="runs/acme"))

res = Controller(plan,
                 audit=AuditLog("runs/acme/audit.jsonl"),
                 kill=KillSwitch(path="runs/acme/STOP"),
                 evidence=EvidenceStore("runs/acme"),
                 discover=True).run()

write_report(res, "runs/acme/report.md",
             store=EvidenceStore("runs/acme"))
assert AuditLog.verify("runs/acme/audit.jsonl")[0]
```
