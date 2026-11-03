"""
Run configuration / target intake.

Turns an authorized Engagement plus a set of seed URLs into a validated RunPlan:
every seed is authorized (confirmed engagement + mode + scope) before it enters
the plan, out-of-scope or unauthorized seeds are recorded rather than silently
dropped, and the request rate is held at or below a safe ceiling unless the
caller opts out explicitly.

This module only plans. It does not resolve, connect, or scan — the controller
consumes a RunPlan and runs it through the guarded client with the governance
primitives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .governance import Engagement, authorize

# Safe default ceiling for requests/second against a real target. Going above it
# requires allow_fast_rate=True, set deliberately.
PROD_RATE_CEILING = 0.3


@dataclass
class RunOptions:
    mode: str = "observe"
    rate: float = PROD_RATE_CEILING          # requests/second
    burst: int = 3
    max_requests: int = 500                  # hard lifetime cap for the run
    timeout: float = 10.0
    max_redirects: int = 5
    verify_tls: bool = True
    headers: Dict[str, str] = field(default_factory=dict)   # attribution etc.
    output_dir: Optional[str] = None
    allow_fast_rate: bool = False            # opt out of PROD_RATE_CEILING


@dataclass
class RunPlan:
    engagement: Engagement
    seeds: List[str]                         # authorized, normalized, de-duplicated
    options: RunOptions
    rejected: List[Tuple[str, str]] = field(default_factory=list)  # (url, reason)

    def summary(self) -> str:
        return (f"program={self.engagement.program} mode={self.options.mode} "
                f"seeds={len(self.seeds)} rejected={len(self.rejected)} "
                f"rate={self.options.rate}/s cap={self.options.max_requests}")


def build_run_plan(engagement: Engagement, seeds, options: Optional[RunOptions] = None) -> RunPlan:
    """Validate seeds against the engagement and produce a RunPlan. Fail-closed:
    raises ValueError if nothing is left to run or the rate ceiling is exceeded
    without an explicit opt-out."""
    options = options or RunOptions()

    if options.rate <= 0:
        raise ValueError("RunOptions.rate must be positive.")
    if options.max_requests <= 0:
        raise ValueError("RunOptions.max_requests must be positive.")
    if options.rate > PROD_RATE_CEILING and not options.allow_fast_rate:
        raise ValueError(
            f"rate {options.rate}/s exceeds the {PROD_RATE_CEILING}/s ceiling; "
            f"set RunOptions.allow_fast_rate=True to override deliberately."
        )
    if options.mode not in engagement.modes:
        raise ValueError(
            f"mode '{options.mode}' not permitted for engagement "
            f"'{engagement.program}' (allowed: {list(engagement.modes)})."
        )

    kept: List[str] = []
    rejected: List[Tuple[str, str]] = []
    seen = set()

    for seed in seeds:
        url = (seed or "").strip()
        if not url:
            continue
        if url in seen:
            continue
        seen.add(url)
        decision = authorize(engagement, url, mode=options.mode)
        if decision.allowed:
            kept.append(url)
        else:
            rejected.append((url, decision.reason))

    if not kept:
        detail = "; ".join(f"{u}: {r}" for u, r in rejected) or "no seeds provided"
        raise ValueError(f"No authorized seeds to run. {detail}")

    return RunPlan(engagement=engagement, seeds=kept, options=options, rejected=rejected)
