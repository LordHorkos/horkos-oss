# KASABONKA — the target-selection brain

Decides whether a bug-bounty target is worth your four weeks, before you spend
them. KASABONKA is a deterministic, rule-based scorer (no LLM, no network, no
dependency) that encodes a published target-selection methodology: six factors
scored out of five — 30 total — with commit / learn / drop thresholds.

## Factors

| Factor | 5 points when… |
|---|---|
| scope_size | focused scope you can read in ~30 min (wildcard scores low) |
| features | several high-value surfaces (roles, sharing, payments, uploads, api, admin) |
| tech_familiarity | a stack you know; hard-to-test tech (WebSocket, GraphQL-authz, IoT, blockchain) penalizes |
| hunter_density | low competition (small Hall of Fame, quiet recent activity) |
| program_age | recently launched (< 6 months) |
| platform_type | VDP / low-competition over a crowded public program |

**Verdict:** ≥ 25 commit · 18–24 learn · < 18 drop.

## Usage

```python
from horkos_sec import KASABONKA, TargetProfile

k = KASABONKA()
score = k.score(TargetProfile(
    program="acme",
    scope="focused",
    features=["roles", "payments", "uploads"],
    tech_familiarity="high", tech_stack=["rest"],
    hall_of_fame=20, program_age_months=3, last_resolved_days=90,
    platform="vdp",
))
print(score.summary())          # "acme: 28/30 — commit"
for name, (s, mx, why) in score.factors.items():
    print(f"  {name}: {s}/{mx}  ({why})")
for r in score.recommendations:
    print("  →", r)
```

## Fed from a run

After an observe-only run, `k.signals_from_run(result)` suggests some profile
inputs from what the scanner actually saw (pages observed → scope hint; finding
URLs/categories → feature hints like uploads/payments/admin). It only surfaces
signals; you confirm the judgment factors.

```python
sig = k.signals_from_run(result)   # {"pages_observed":.., "suggested_scope":..., "suggested_features":[...]}
```

## In the dashboard

Pass a `TargetScore` to the HTML dashboard and the scorecard is merged on top of
the findings:

```python
from horkos_sec import write_html_report
write_html_report(result, "runs/acme/dashboard.html", store=store, target_score=score)
```

## Principles it applies

`KASABONKA.principles` holds the methodology's guidance in plain terms — payout
shouldn't drive the choice, favor focused scopes and familiar tech, hunt where
logic flaws live, run a 2-hour recon pass, commit ~4 weeks. The methodology is
encoded as logic; the scorer is this project's own implementation, inspired by
public target-selection guidance.

## Tests

```bash
python3 tests/test_kasabonka.py     # or: python -m pytest
```
