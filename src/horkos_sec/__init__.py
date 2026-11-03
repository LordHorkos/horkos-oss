"""
horkos_sec — a small, dependency-free request-safety toolkit.

Five composable pieces for building a fail-closed outbound-HTTP path:

  scope_guard    — is this URL in scope? (allow/deny domain matching)
  safe_resolver  — does the host resolve to a safe address? (SSRF-safe)
  request_guard  — gate each request: method + cap + scope + resolve
  rate_limiter   — token-bucket throttle with a hard global cap
  severity       — cap findings into a restricted band without dropping them

The guard composes the others; see the README for a wiring example.
"""

from .governance import (
    Engagement, authorize, AuthDecision, AuditLog, KillSwitch, Aborted,
)
from .hackerone_scope import parse_hackerone_scope, ParsedScope
from .http_client import GuardedHTTPClient, FetchResult
from .rate_limiter import TokenBucket
from .request_guard import RequestGuard, GuardDecision, ALLOWED_METHODS
from .safe_resolver import resolve, validate_ip, ResolvedTarget
from .scope_guard import check_scope, ScopeConfig, ScopeResult
from .severity import cap_severity, with_true_severity

__version__ = "0.4.0"

__all__ = [
    "Engagement",
    "authorize",
    "AuthDecision",
    "AuditLog",
    "KillSwitch",
    "Aborted",
    "GuardedHTTPClient",
    "FetchResult",
    "TokenBucket",
    "RequestGuard",
    "GuardDecision",
    "ALLOWED_METHODS",
    "resolve",
    "validate_ip",
    "ResolvedTarget",
    "check_scope",
    "ScopeConfig",
    "ScopeResult",
    "parse_hackerone_scope",
    "ParsedScope",
    "cap_severity",
    "with_true_severity",
]
