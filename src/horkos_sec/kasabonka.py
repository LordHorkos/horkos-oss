"""
KASABONKA — the target-selection brain.

A deterministic, rule-based scorer that decides whether a bug-bounty target is
worth your four weeks. It encodes a published target-selection methodology (six
factors scored out of five, 30 total, with commit / learn / drop thresholds and
recon principles) as logic — not as copied text. Give it a TargetProfile and it
returns a per-factor score, a total, a verdict, and plain next-step guidance.

It is "fed" two things: the methodology (baked into the factor logic below) and,
optionally, signals from a finished observe-only run (`signals_from_run`) that
suggest some factor inputs from what the scanner actually saw. The human still
confirms the judgment factors — tech familiarity and the like are yours to set.

No LLM, no network, no dependency: a brain in the expert-system sense.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Verdict thresholds (out of 30).
_COMMIT = 25
_LEARN = 18

# Tech choices the methodology flags as hard to test / low-yield for most hunters.
_HARD_TECH = ("websocket", "graphql-authz", "iot", "hardware", "blockchain", "smart-contract")

# High-value feature surfaces (logic/access-control bugs tend to live here).
_VALUE_FEATURES = ("roles", "sharing", "payments", "uploads", "api", "multi-tenant",
                   "invitations", "impersonation", "admin")

_PRINCIPLES = [
    "Let testability, not payout size, drive the choice — a big bounty on a stack you can't test is worthless.",
    "Favor focused scopes you can read end to end in ~30 minutes over sprawling wildcards.",
    "Pick technologies you already understand; standard REST/web apps beat exotic stacks.",
    "Prefer low-competition programs (VDPs, short Hall-of-Fame, recently launched).",
    "Hunt where logic flaws live: access control, business flows, roles, payments, uploads.",
    "Run a ~2-hour recon pass first: two accounts, map roles and features, find the API docs.",
    "Commit to one target for about four weeks instead of switching constantly.",
]


@dataclass
class TargetProfile:
    program: str = ""
    # scope: "focused" | "moderate" | "wildcard"
    scope: str = "moderate"
    # distinct high-value features present (see _VALUE_FEATURES)
    features: List[str] = field(default_factory=list)
    # tech familiarity: "high" | "medium" | "low"
    tech_familiarity: str = "medium"
    # technologies in use (lowercased); any in _HARD_TECH penalize familiarity
    tech_stack: List[str] = field(default_factory=list)
    # hunter-density signals
    hall_of_fame: Optional[int] = None        # number of names
    program_age_months: Optional[float] = None
    last_resolved_days: Optional[float] = None  # days since last resolved report
    # platform: "vdp" | "private" | "public"
    platform: str = "public"


@dataclass
class TargetScore:
    program: str
    factors: Dict[str, Tuple[int, int, str]]   # name -> (score, max, note)
    total: int
    verdict: str                               # "commit" | "learn" | "drop"
    recommendations: List[str]

    def summary(self) -> str:
        return f"{self.program or 'target'}: {self.total}/30 — {self.verdict}"


def _score_scope(p: TargetProfile):
    return {"focused": 5, "moderate": 3, "wildcard": 1}.get(p.scope, 3), \
        f"scope '{p.scope}'"


def _score_features(p: TargetProfile):
    n = len({f.lower() for f in p.features} & set(_VALUE_FEATURES))
    score = min(5, n + 1) if n else 1
    return score, f"{n} high-value feature(s)"


def _score_tech(p: TargetProfile):
    base = {"high": 5, "medium": 3, "low": 1}.get(p.tech_familiarity, 3)
    hard = sorted({t.lower() for t in p.tech_stack} & set(_HARD_TECH))
    if hard:
        base = max(1, base - 2)
        return base, f"familiarity '{p.tech_familiarity}', hard tech: {', '.join(hard)}"
    return base, f"familiarity '{p.tech_familiarity}'"


def _score_density(p: TargetProfile):
    # Lower competition -> higher score. Combine Hall-of-Fame size, recency of the
    # last resolved report, with sensible scoring when a signal is unknown.
    pts, notes = [], []
    if p.hall_of_fame is not None:
        if p.hall_of_fame < 50:
            pts.append(5); notes.append(f"HoF {p.hall_of_fame} (low)")
        elif p.hall_of_fame < 200:
            pts.append(3); notes.append(f"HoF {p.hall_of_fame} (moderate)")
        else:
            pts.append(1); notes.append(f"HoF {p.hall_of_fame} (saturated)")
    if p.last_resolved_days is not None:
        # a very recent resolve means active competitors
        if p.last_resolved_days > 60:
            pts.append(5); notes.append("quiet recently")
        elif p.last_resolved_days > 14:
            pts.append(3); notes.append("some recent activity")
        else:
            pts.append(1); notes.append("hot right now")
    if not pts:
        return 3, "density unknown"
    return round(sum(pts) / len(pts)), "; ".join(notes)


def _score_age(p: TargetProfile):
    m = p.program_age_months
    if m is None:
        return 3, "age unknown"
    if m < 6:
        return 5, f"{m:.0f}mo (new)"
    if m < 12:
        return 4, f"{m:.0f}mo"
    if m < 24:
        return 3, f"{m:.0f}mo"
    return 2, f"{m:.0f}mo (mature)"


def _score_platform(p: TargetProfile):
    return {"vdp": 5, "private": 4, "public": 2}.get(p.platform, 2), f"{p.platform}"


_FACTORS = [
    ("scope_size", _score_scope),
    ("features", _score_features),
    ("tech_familiarity", _score_tech),
    ("hunter_density", _score_density),
    ("program_age", _score_age),
    ("platform_type", _score_platform),
]


class KASABONKA:
    """The target-selection brain. Stateless; holds the methodology."""

    principles = list(_PRINCIPLES)

    def score(self, profile: TargetProfile) -> TargetScore:
        factors: Dict[str, Tuple[int, int, str]] = {}
        total = 0
        for name, fn in _FACTORS:
            s, note = fn(profile)
            s = max(0, min(5, int(s)))
            factors[name] = (s, 5, note)
            total += s
        verdict = "commit" if total >= _COMMIT else "learn" if total >= _LEARN else "drop"
        return TargetScore(profile.program, factors, total, verdict,
                           self._recommend(profile, verdict))

    def _recommend(self, p: TargetProfile, verdict: str) -> List[str]:
        recs: List[str] = []
        if verdict == "commit":
            recs.append("Strong fit — commit ~4 weeks. Start with a 2-hour recon pass.")
        elif verdict == "learn":
            recs.append("Acceptable for learning, not a high-yield bet. Time-box it.")
        else:
            recs.append("Score below threshold — drop it and find a better-fit target.")
        if p.scope == "wildcard":
            recs.append("Wildcard scope: narrow to a focused asset you can read in ~30 min.")
        if {t.lower() for t in p.tech_stack} & set(_HARD_TECH):
            recs.append("Hard-to-test tech present — only proceed if it's genuinely your strength.")
        if p.platform == "vdp":
            recs.append("VDP: expect recognition, not cash — fine for reputation/learning.")
        if not p.features:
            recs.append("No high-value features noted — recon for roles/sharing/payments/uploads.")
        return recs

    def signals_from_run(self, result) -> Dict[str, object]:
        """Suggest a partial profile from a finished observe-only run. The human
        confirms; this only surfaces what the scanner saw, it does not decide."""
        pages = len(getattr(result, "fetches", []))
        # value-feature hints from finding URLs/categories
        hints = set()
        kw = {"upload": "uploads", "pay": "payments", "admin": "admin",
              "invite": "invitations", "role": "roles", "share": "sharing", "api": "api"}
        for f in getattr(result, "findings", []):
            blob = (f.url + " " + f.category).lower()
            for k, feat in kw.items():
                if k in blob:
                    hints.add(feat)
        scope = "focused" if pages and pages <= 20 else "moderate"
        return {"pages_observed": pages, "suggested_scope": scope,
                "suggested_features": sorted(hints)}
