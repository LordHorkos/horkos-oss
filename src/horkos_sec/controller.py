"""
Controller — run a RunPlan through the guarded client, accountably.

Composes everything the toolkit has built:

  RunPlan (authorized seeds, options)
     -> RequestGuard  (scope_guard + safe_resolver)
     -> TokenBucket   (rate + hard cap)
     -> GuardedHTTPClient (pinned, attributed, recording egress)

and wraps the loop in governance: every seed is re-authorized at run time
(defense in depth — the plan already authorized them, but modes/scope are
re-checked at the moment of use), the KillSwitch is checked before each fetch,
and every authorization decision and request is written to the AuditLog.

Observe-only: it issues GET against each seed and records the response. It does
not crawl, mutate, or run detectors — those are later, separate layers that
consume a RunResult. Nothing here decides on its own to go beyond the plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import partial
from typing import List, Optional

from .governance import AuditLog, Aborted, KillSwitch, authorize
from .http_client import FetchResult, GuardedHTTPClient
from .rate_limiter import TokenBucket
from .request_guard import RequestGuard
from .run_config import RunPlan
from .safe_resolver import resolve
from .scope_guard import check_scope


@dataclass
class FetchRecord:
    url: str
    ok: bool
    status: Optional[int] = None
    ip: str = ""
    reason: str = ""
    redirects: List[str] = field(default_factory=list)


@dataclass
class RunResult:
    plan: RunPlan
    fetches: List[FetchRecord] = field(default_factory=list)
    aborted: bool = False
    abort_reason: str = ""

    def summary(self) -> str:
        ok = sum(1 for f in self.fetches if f.ok)
        return (f"{self.plan.engagement.program}: {ok}/{len(self.fetches)} ok"
                + (f" (ABORTED: {self.abort_reason})" if self.aborted else ""))


class Controller:
    def __init__(self, plan: RunPlan, audit: Optional[AuditLog] = None,
                 kill: Optional[KillSwitch] = None, resolve_allow_private: bool = False):
        self._plan = plan
        self._audit = audit
        self._kill = kill or KillSwitch()

        opt = plan.options
        guard = RequestGuard(
            scope_check=partial(check_scope, scope=plan.engagement.scope),
            resolve=partial(resolve, allow_private=resolve_allow_private),
            max_requests=opt.max_requests,
        )
        bucket = TokenBucket(rate=opt.rate, burst=opt.burst, max_requests=opt.max_requests)
        self._client = GuardedHTTPClient(
            guard, bucket=bucket, headers=opt.headers, timeout=opt.timeout,
            max_redirects=opt.max_redirects, verify_tls=opt.verify_tls,
        )

    def _log(self, action: str, **fields) -> None:
        if self._audit is not None:
            self._audit.record(action, **fields)

    def run(self) -> RunResult:
        plan = self._plan
        mode = plan.options.mode
        result = RunResult(plan=plan)
        self._log("run_start", program=plan.engagement.program, mode=mode,
                  seeds=len(plan.seeds))

        for url in plan.seeds:
            try:
                self._kill.check()
            except Aborted as e:
                result.aborted = True
                result.abort_reason = str(e)
                self._log("aborted", reason=str(e))
                break

            # Re-authorize at the moment of use (defense in depth).
            decision = authorize(plan.engagement, url, mode=mode)
            self._log("authorize", url=url, allowed=decision.allowed, reason=decision.reason)
            if not decision.allowed:
                result.fetches.append(FetchRecord(url, False, reason=decision.reason))
                continue

            r: FetchResult = self._client.fetch(url, method="GET")
            self._log("request", url=url, ok=r.ok, status=r.status, ip=r.ip,
                      reason=r.reason, redirects=len(r.redirects))
            result.fetches.append(
                FetchRecord(url=url, ok=r.ok, status=r.status, ip=r.ip,
                            reason=r.reason, redirects=r.redirects)
            )

        self._log("run_end", program=plan.engagement.program,
                  fetched=len(result.fetches), aborted=result.aborted)
        return result
