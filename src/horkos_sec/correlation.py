"""
Correlation / triage — collapse raw findings into a ranked set of unique issues.

A passive run emits one Finding per (category, title, URL): the same missing
security header on twelve pages is twelve findings. For a human — or a bug-bounty
program now drowning in AI-generated noise — that is slop, not signal. This module
turns the raw list into the thing an operator actually acts on:

  * group findings across URLs into one Issue per (category, title-family), with
    the affected URLs, an occurrence count, and the evidence ids preserved;
  * score each Issue's confidence with a transparent rule (true severity + the
    finding's own CVSS weight + cross-run stability) — no model, no network;
  * split issues at an emit floor into *surfaced* (worth reporting) and
    *suppressed* (kept, counted, never silently dropped), so the headline is a
    handful of real candidates instead of sixty rows of header hygiene.

Nothing is destroyed: the raw findings stay on the RunResult, in run.json, and in
the audit trail. Correlation is a *view*, applied at report/dashboard time. That
keeps the append-only, evidence-first discipline intact while fixing the one
output profile that 2026 programs punish: unvalidated volume.

Cross-run stability is the one piece of real intelligence here. An issue that
recurs across the last N runs of the same program is more likely real than a
one-off; a brand-new issue against a known surface is worth a second look. Pass
prior runs' issue keys to `correlate(...)` to light that up.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .report import _CWE_CVSS_PREFIX, _cwe_cvss, _true_severity, _clean_detail
from .findings import Finding

# Confidence weight per TRUE severity (the real level, before the info/low/medium
# display cap). Deliberately conservative: a missing header is not a finding you
# submit, a leaked key is.
_SEV_W = {"info": 0.20, "low": 0.45, "medium": 0.65, "high": 0.85, "critical": 0.95}

# Issues at or above this confidence are surfaced; below it they are suppressed
# (kept and counted, not dropped). 0.5 cleanly demotes header-absence noise while
# surfacing secrets, stack traces, CORS-with-credentials, directory listing, etc.
DEFAULT_EMIT_FLOOR = 0.5

# For ordering within equal confidence.
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Number of most-recent prior runs that still contribute to the stability signal.
STABILITY_WINDOW = 5

IssueKey = Tuple[str, str]  # (category, title-family)


@dataclass
class Issue:
    category: str
    title: str                       # the title-family (stable grouping label)
    severity: str                    # capped: info / low / medium
    true_severity: str               # real level (may be high/critical)
    detail: str                      # representative, cleaned
    urls: List[str] = field(default_factory=list)   # affected, unique, sorted
    count: int = 0                   # raw occurrences folded into this issue
    evidence_ids: List[str] = field(default_factory=list)
    cwe: str = ""
    cvss: str = ""
    cvss_score: float = 0.0
    confidence: float = 0.0
    prior_seen: int = 0              # how many prior runs (in window) had this issue
    stable: bool = False             # recurs across prior runs -> more likely real
    is_new: bool = False             # unseen against a surface we have prior runs for

    def key(self) -> IssueKey:
        return (self.category, self.title)

    def to_dict(self) -> Dict:
        return {
            "category": self.category, "title": self.title,
            "severity": self.severity, "true_severity": self.true_severity,
            "detail": self.detail, "urls": list(self.urls), "count": self.count,
            "evidence_ids": list(self.evidence_ids),
            "cwe": self.cwe, "cvss": self.cvss, "cvss_score": self.cvss_score,
            "confidence": self.confidence, "prior_seen": self.prior_seen,
            "stable": self.stable, "is_new": self.is_new,
        }

    @staticmethod
    def from_dict(d: Dict) -> "Issue":
        return Issue(
            category=d.get("category", ""), title=d.get("title", ""),
            severity=d.get("severity", "info"), true_severity=d.get("true_severity", "info"),
            detail=d.get("detail", ""), urls=list(d.get("urls") or []),
            count=int(d.get("count", 0)), evidence_ids=list(d.get("evidence_ids") or []),
            cwe=d.get("cwe", ""), cvss=d.get("cvss", ""),
            cvss_score=float(d.get("cvss_score", 0.0)),
            confidence=float(d.get("confidence", 0.0)), prior_seen=int(d.get("prior_seen", 0)),
            stable=bool(d.get("stable")), is_new=bool(d.get("is_new")),
        )


@dataclass
class Correlation:
    issues: List[Issue] = field(default_factory=list)        # surfaced, ranked
    suppressed: List[Issue] = field(default_factory=list)    # below floor, preserved
    emit_floor: float = DEFAULT_EMIT_FLOOR
    raw_count: int = 0                                       # total raw findings
    prior_runs: int = 0                                      # prior runs considered

    @property
    def unique_count(self) -> int:
        return len(self.issues) + len(self.suppressed)

    def summary(self) -> str:
        return (f"{self.raw_count} observations -> {self.unique_count} unique "
                f"({len(self.issues)} surfaced, {len(self.suppressed)} low-confidence)")

    def to_dict(self) -> Dict:
        return {
            "emit_floor": self.emit_floor, "raw_count": self.raw_count,
            "prior_runs": self.prior_runs,
            "surfaced_count": len(self.issues),
            "surfaced": [i.to_dict() for i in self.issues],
            "suppressed": [i.to_dict() for i in self.suppressed],
        }

    @staticmethod
    def from_dict(d: Dict) -> "Correlation":
        return Correlation(
            issues=[Issue.from_dict(x) for x in (d.get("surfaced") or [])],
            suppressed=[Issue.from_dict(x) for x in (d.get("suppressed") or [])],
            emit_floor=float(d.get("emit_floor", DEFAULT_EMIT_FLOOR)),
            raw_count=int(d.get("raw_count", 0)),
            prior_runs=int(d.get("prior_runs", 0)),
        )


def family(title: str) -> str:
    """Collapse a variable-suffixed title (e.g. 'Private key exposed (RSA)' or
    'Technology/version disclosure: nginx/1.25') to its stable family, so the same
    class of finding groups into one issue across pages. Falls back to the title."""
    for prefix in _CWE_CVSS_PREFIX:
        if title.startswith(prefix):
            return prefix
    # A "<family>: <detail>" title groups on the part before the first colon.
    head = title.split(":", 1)[0].strip()
    return head or title


def _confidence(true_sev: str, cvss_score: float, prior_seen: int) -> float:
    base = _SEV_W.get(true_sev, 0.2)
    stability_bonus = (min(prior_seen, 3) / 3.0) * 0.10
    c = base * 0.60 + (cvss_score / 10.0) * 0.30 + stability_bonus
    return round(max(0.0, min(0.99, c)), 2)


def correlate(findings: Sequence[Finding],
              prior: Optional[Sequence[Set[IssueKey]]] = None,
              emit_floor: float = DEFAULT_EMIT_FLOOR) -> Correlation:
    """Fold raw findings into ranked unique Issues.

    prior: issue-key sets from the most-recent prior runs of the same program
    (newest first is fine; order is not significant). Used only to compute the
    stability / new-issue signal. None or empty means no stability input.
    """
    prior_sets: List[Set[IssueKey]] = list(prior or [])[:STABILITY_WINDOW]

    groups: Dict[IssueKey, List[Finding]] = {}
    for f in findings:
        groups.setdefault((f.category, family(f.title)), []).append(f)

    issues: List[Issue] = []
    for (category, fam), members in groups.items():
        rep = members[0]
        true_sev = _true_severity(rep)
        cwe, cvss, score = _cwe_cvss(rep)
        urls = sorted({m.url for m in members if m.url})
        eids = []
        for m in members:
            eid = m.evidence.get("evidence_id")
            if eid and eid not in eids:
                eids.append(eid)
        prior_seen = sum(1 for s in prior_sets if (category, fam) in s)
        conf = _confidence(true_sev, score, prior_seen)
        issues.append(Issue(
            category=category, title=fam,
            severity=rep.severity, true_severity=true_sev,
            detail=_clean_detail(rep),
            urls=urls, count=len(members), evidence_ids=eids[:20],
            cwe=cwe, cvss=cvss, cvss_score=score,
            confidence=conf,
            prior_seen=prior_seen,
            stable=prior_seen >= 2,
            is_new=bool(prior_sets) and prior_seen == 0,
        ))

    def rank(i: Issue):
        return (-i.confidence, _SEV_ORDER.get(i.true_severity, 5), i.category, i.title)

    issues.sort(key=rank)
    surfaced = [i for i in issues if i.confidence >= emit_floor]
    suppressed = [i for i in issues if i.confidence < emit_floor]
    return Correlation(issues=surfaced, suppressed=suppressed,
                       emit_floor=emit_floor, raw_count=len(findings),
                       prior_runs=len(prior_sets))


def prior_issue_keys(runs_root: str, program: str,
                     exclude_id: Optional[str] = None,
                     window: int = STABILITY_WINDOW) -> List[Set[IssueKey]]:
    """Load issue-key sets from the most-recent prior runs of `program` under
    `runs_root` (a directory of run dirs). Newest first, at most `window`. Used to
    feed correlate()'s stability signal. Best-effort: unreadable runs are skipped.
    """
    from .persistence import list_runs, load_run
    import os

    out: List[Set[IssueKey]] = []
    for meta in list_runs(runs_root):               # already newest-first
        if meta.get("program") != program:
            continue
        rid = meta.get("id")
        if exclude_id is not None and rid == exclude_id:
            continue
        try:
            data = load_run(os.path.join(runs_root, rid))
        except (OSError, ValueError):
            continue
        keys: Set[IssueKey] = set()
        for f in data.get("findings", []):
            keys.add((f.get("category", ""), family(f.get("title", ""))))
        out.append(keys)
        if len(out) >= window:
            break
    return out
