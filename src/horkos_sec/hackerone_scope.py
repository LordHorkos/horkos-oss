"""
Parse a pasted HackerOne program scope into a ScopeConfig the toolkit runs on.

Accepts three paste shapes and auto-detects which it got:

  1. Structured-scopes JSON from the HackerOne API
     (`.../programs/<handle>/structured_scopes`): either the raw
     `{"data": [{"attributes": {...}}, ...]}` envelope or a bare list of
     attribute objects. Each entry's `asset_type`, `asset_identifier`, and
     `eligible_for_submission` are read.

  2. A list of asset objects: `[{"asset_identifier": "...", "asset_type": "...",
     "eligible_for_submission": true/false}, ...]`.

  3. Plain text — one asset per line, as copied from the program's scope table.
     An out-of-scope line is recognised by a trailing/leading marker containing
     "out of scope" / "out-of-scope" / "excluded", or by a leading "-".
     A wildcard (`*.example.com` or `.example.com`) becomes a subtree; a bare
     host becomes an exact in-scope host.

Only URL/WILDCARD/DOMAIN-type web assets are mapped. Non-web asset types
(CIDR, IP range, mobile app packages, source-code repos, hardware, "OTHER",
etc.) are collected into `ParsedScope.skipped` rather than guessed at — a URL
scope guard has nothing safe to do with a `com.example.app` package id.

The result is intentionally conservative and fail-closed downstream: anything
the parser is unsure about is skipped and reported, never silently admitted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlparse

from .scope_guard import ScopeConfig

# Asset types HackerOne uses for web endpoints we can turn into host scope.
_WEB_ASSET_TYPES = {"URL", "WILDCARD", "DOMAIN", "API", "WEBSITE", ""}

_OUT_MARKERS = ("out of scope", "out-of-scope", "excluded", "not in scope")


@dataclass
class ParsedScope:
    config: ScopeConfig
    in_scope_wildcards: List[str] = field(default_factory=list)
    in_scope_hosts: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)   # "identifier (reason)"

    def summary(self) -> str:
        return (
            f"{len(self.in_scope_wildcards)} wildcard, {len(self.in_scope_hosts)} exact host, "
            f"{len(self.out_of_scope)} out-of-scope, {len(self.skipped)} skipped"
        )


def parse_hackerone_scope(text: str, allowed_schemes: List[str] | None = None) -> ParsedScope:
    """Parse pasted HackerOne scope text/JSON into a ParsedScope (with .config)."""
    if not text or not text.strip():
        raise ValueError("Empty scope input.")

    entries = _load_entries(text)

    wildcards: List[str] = []
    hosts: List[str] = []
    out: List[str] = []
    skipped: List[str] = []

    for ident, asset_type, eligible in entries:
        ident = (ident or "").strip()
        if not ident:
            continue
        asset_type = (asset_type or "").strip().upper()

        if asset_type and asset_type not in _WEB_ASSET_TYPES:
            skipped.append(f"{ident} (asset_type {asset_type})")
            continue

        host, is_wildcard = _normalize_host(ident)
        if not host:
            skipped.append(f"{ident} (no host)")
            continue

        if not eligible:
            # Out of scope: wildcard -> subtree, bare host -> exact (scope_guard
            # disallowed semantics), so prefix a wildcard with a dot.
            out.append("." + host if is_wildcard else host)
        elif is_wildcard:
            wildcards.append(host)
        else:
            hosts.append(host)

    wildcards = _dedupe(wildcards)
    hosts = _dedupe([h for h in hosts if h not in wildcards])
    out = _dedupe(out)

    if not wildcards and not hosts:
        raise ValueError(
            "No in-scope web assets found. Skipped: " + ("; ".join(skipped) or "none")
        )

    config = ScopeConfig(
        allowed_domains=wildcards,
        allowed_exact=hosts,
        disallowed_domains=out,
        allowed_schemes=list(allowed_schemes or ["https"]),
    )
    return ParsedScope(config, wildcards, hosts, out, skipped)


# ---- input loading ----------------------------------------------------------

def _load_entries(text: str):
    """Yield (asset_identifier, asset_type, eligible: bool) from any paste shape."""
    stripped = text.lstrip()
    if stripped[:1] in "[{":
        try:
            return _entries_from_json(json.loads(text))
        except (ValueError, TypeError, KeyError):
            pass  # fall through to text parsing
    return _entries_from_text(text)


def _entries_from_json(doc):
    if isinstance(doc, dict):
        items = doc.get("data", doc.get("structured_scopes", []))
    else:
        items = doc
    if not isinstance(items, list):
        raise ValueError("Unrecognised JSON scope shape.")

    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        attrs = item.get("attributes", item)  # API envelope or bare object
        ident = attrs.get("asset_identifier") or attrs.get("identifier") or attrs.get("asset")
        atype = attrs.get("asset_type") or attrs.get("type") or ""
        eligible = attrs.get("eligible_for_submission")
        if eligible is None:
            eligible = attrs.get("in_scope", True)
        out.append((ident, atype, bool(eligible)))
    return out


def _entries_from_text(text: str):
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        eligible = not any(m in low for m in _OUT_MARKERS)
        if line.startswith("-"):
            eligible = False
            line = line[1:].strip()
        # Take the first whitespace/comma/pipe/tab field as the asset identifier.
        ident = line.replace("\t", " ").replace("|", " ").replace(",", " ").split()[0]
        out.append((ident, "", eligible))
    return out


# ---- host normalization -----------------------------------------------------

def _normalize_host(ident: str):
    """Return (host, is_wildcard). host is '' if no host could be extracted."""
    s = ident.strip().strip('"').strip()
    is_wildcard = False

    if s.startswith("*."):
        is_wildcard = True
        s = s[2:]
    elif s.startswith("."):
        is_wildcard = True
        s = s[1:]

    if "://" in s:
        s = urlparse(s).hostname or ""
    else:
        # strip any path/port fragment a bare "host/path" or "host:443" carries
        s = s.split("/")[0].split(":")[0]

    s = s.strip().strip(".").lower()
    if "*" in s or " " in s or "." not in s:
        return "", is_wildcard
    return s, is_wildcard


def _dedupe(items: List[str]) -> List[str]:
    seen: dict = {}
    for it in items:
        seen.setdefault(it, None)
    return list(seen)
