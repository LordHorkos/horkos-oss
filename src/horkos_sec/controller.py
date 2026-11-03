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

Observe-only: it issues GET against seeds (optionally crawling in-scope links
with `discover=True`) and runs the passive detectors on each response
(`detect=True`), collecting de-duplicated findings into the RunResult. It never
mutates or injects, and never goes beyond the authorized, in-scope surface.
Active checks remain a separate, opt-in layer outside this controller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import partial
from typing import List, Optional

from .detectors import run_passive_detectors
from .discovery import crawl
from .evidence import EvidenceStore
from .findings import Finding
from .governance import AuditLog, Aborted, KillSwitch, authorize
from .http_client import FetchResult, GuardedHTTPClient
from .rate_limiter import TokenBucket
from .request_guard import RequestGuard
from .run_config import RunPlan
from .safe_resolver import resolve, ResolutionCache
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
    findings: List[Finding] = field(default_factory=list)
    aborted: bool = False
    abort_reason: str = ""

    def summary(self) -> str:
        ok = sum(1 for f in self.fetches if f.ok)
        return (f"{self.plan.engagement.program}: {ok}/{len(self.fetches)} ok, "
                f"{len(self.findings)} findings"
                + (f" (ABORTED: {self.abort_reason})" if self.aborted else ""))


class Controller:
    def __init__(self, plan: RunPlan, audit: Optional[AuditLog] = None,
                 kill: Optional[KillSwitch] = None, resolve_allow_private: bool = False,
                 detect: bool = True, discover: bool = False,
                 max_pages: int = 50, max_depth: int = 3,
                 evidence: Optional[EvidenceStore] = None):
        self._plan = plan
        self._audit = audit
        self._kill = kill or KillSwitch()
        self._detect = detect
        self._discover = discover
        self._max_pages = max_pages
        self._max_depth = max_depth
        # Capture evidence if a store is given, or if the plan names an output dir.
        if evidence is None and plan.options.output_dir:
            evidence = EvidenceStore(plan.options.output_dir)
        self._evidence = evidence

        opt = plan.options
        self._dns_cache = ResolutionCache()
        guard = RequestGuard(
            scope_check=partial(check_scope, scope=plan.engagement.scope),
            resolve=partial(resolve, allow_private=resolve_allow_private, cache=self._dns_cache),
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
                  seeds=len(plan.seeds), discover=self._discover, detect=self._detect)

        seen_keys = set()

        def record_findings(r: FetchResult) -> None:
            if not r.ok:
                return
            eid = ""
            if self._evidence is not None:
                eid = self._evidence.save_response(
                    r, request_headers={"Host": "", **plan.options.headers}, method="GET")
            if not self._detect:
                return
            for f in run_passive_detectors(r):
                if f.key() not in seen_keys:
                    seen_keys.add(f.key())
                    if eid:
                        f.evidence["evidence_id"] = eid
                    result.findings.append(f)

        def guarded_fetch(url: str) -> FetchResult:
            self._kill.check()  # raises Aborted, caught below
            decision = authorize(plan.engagement, url, mode=mode)
            self._log("authorize", url=url, allowed=decision.allowed, reason=decision.reason)
            if not decision.allowed:
                result.fetches.append(FetchRecord(url, False, reason=decision.reason))
                return FetchResult(False, url, url, reason=decision.reason)
            r = self._client.fetch(url, method="GET")
            self._log("request", url=url, ok=r.ok, status=r.status, ip=r.ip,
                      reason=r.reason, redirects=len(r.redirects))
            result.fetches.append(FetchRecord(url, r.ok, r.status, r.ip, r.reason, r.redirects))
            record_findings(r)
            return r

        try:
            if self._discover:
                crawl(plan.seeds, fetch=guarded_fetch,
                      in_scope=lambda u: authorize(plan.engagement, u, mode=mode).allowed,
                      max_pages=self._max_pages, max_depth=self._max_depth)
            else:
                for url in plan.seeds:
                    guarded_fetch(url)
        except Aborted as e:
            result.aborted = True
            result.abort_reason = str(e)
            self._log("aborted", reason=str(e))

        self._client.close()  # release pooled keep-alive connections
        self._log("run_end", program=plan.engagement.program,
                  fetched=len(result.fetches), findings=len(result.findings),
                  aborted=result.aborted)
        return result
