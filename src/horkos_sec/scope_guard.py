"""
Scope guard — decide whether a URL is in scope before any request is made.

Fail-closed: anything ambiguous or unparseable is denied. A URL is in scope only
if it parses, its scheme is allowed, its host matches an allowed domain, and its
host matches no disallowed domain (an explicit block always wins).

Two matching subtleties, both deliberate:

  * Allowed domains match a host OR its subdomains by default
    (`example.com` admits `example.com` and `sub.example.com`). Set
    `exact_match=True` to admit only the exact hosts listed — subdomains are
    then refused unless listed themselves.

  * Allowed-exact hosts (`allowed_exact`) are admitted as exact hosts only,
    regardless of `exact_match`. This lets a single config mix wildcard assets
    (subtree, in `allowed_domains`) with specific hosts (exact, in
    `allowed_exact`) — the shape a HackerOne scope usually has.

  * Disallowed domains are stricter: a BARE root blocks only that exact host,
    while a `.`- or `*.`-prefixed entry blocks the whole subtree. So
    `prod.example.com` as a bare disallowed entry does not wrongly reject an
    in-scope `api.stg.example.com`; to block a subtree, write `.prod.example.com`
    or `*.prod.example.com`.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse


@dataclass
class ScopeConfig:
    allowed_domains: List[str] = field(default_factory=list)
    disallowed_domains: List[str] = field(default_factory=list)
    allowed_schemes: List[str] = field(default_factory=lambda: ["https"])
    # exact_match=True => allowed_domains admits ONLY the exact hosts listed;
    # subdomains are refused unless themselves listed.
    exact_match: bool = False
    # Hosts admitted as exact matches only, independent of exact_match. Use for
    # specific in-scope hosts alongside wildcard subtrees in allowed_domains.
    allowed_exact: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.allowed_domains and not self.allowed_exact:
            raise ValueError(
                "ScopeConfig: allowed_domains or allowed_exact must be non-empty."
            )


@dataclass
class ScopeResult:
    in_scope: bool
    reason: Optional[str] = None


def check_scope(url: str, scope: ScopeConfig) -> ScopeResult:
    """
    Returns ScopeResult(in_scope=True) only if ALL conditions pass:
      - parseable URL with a scheme and host
      - scheme in allowed_schemes
      - hostname matches an allowed_domain
      - hostname does NOT match a disallowed_domain
    """
    try:
        parsed = urlparse(url)
    except Exception as e:
        return ScopeResult(False, f"URL parse failed: {e}")

    if not parsed.scheme or not parsed.netloc:
        return ScopeResult(False, f"URL missing scheme or host: {url!r}")

    if parsed.scheme not in scope.allowed_schemes:
        return ScopeResult(
            False,
            f"Scheme '{parsed.scheme}' not in allowed_schemes {scope.allowed_schemes}."
        )

    hostname = parsed.hostname or ""
    if not hostname:
        return ScopeResult(False, "Could not extract hostname from URL.")

    # Disallowed check first — an explicit block wins.
    for blocked in scope.disallowed_domains:
        if _matches_disallowed(hostname, blocked):
            return ScopeResult(
                False,
                f"Hostname '{hostname}' matches disallowed domain '{blocked}'."
            )

    for allowed in scope.allowed_exact:
        if _matches(hostname, allowed, exact=True):
            return ScopeResult(True)

    for allowed in scope.allowed_domains:
        if _matches(hostname, allowed, exact=scope.exact_match):
            return ScopeResult(True)

    return ScopeResult(
        False,
        f"Hostname '{hostname}' is not in scope "
        f"(allowed_domains={scope.allowed_domains}, allowed_exact={scope.allowed_exact})."
    )


def _matches(hostname: str, pattern: str, exact: bool = False) -> bool:
    """
    ALLOWED-domain matching. Default: exact OR subdomain match — pattern
    'example.com' matches 'example.com' and 'sub.example.com'. With exact=True,
    ONLY the exact host matches ('sub.example.com' is REFUSED unless listed).
    """
    hostname = hostname.lower().strip(".")
    pattern = pattern.lower().strip(".")
    if exact:
        return hostname == pattern
    return hostname == pattern or hostname.endswith("." + pattern)


def _matches_disallowed(hostname: str, pattern: str) -> bool:
    """
    DISALLOWED-domain matching, stricter than _matches:
      - bare root 'example.com'            -> EXACT host only (no subdomains)
      - '.example.com' / '*.example.com'   -> whole subtree
    A bare disallowed root therefore cannot swallow an in-scope sibling subtree;
    prefix with '.' or '*.' to block a subtree deliberately.
    """
    hostname = hostname.lower().strip(".")
    pattern = pattern.lower().strip()
    if pattern.startswith("*."):
        base = pattern[2:].strip(".")
    elif pattern.startswith("."):
        base = pattern[1:].strip(".")
    else:
        return hostname == pattern.strip(".")
    return bool(base) and (hostname == base or hostname.endswith("." + base))
