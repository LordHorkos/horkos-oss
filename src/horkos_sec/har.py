"""
HAR ingestion — pull endpoints a SPA only reveals at runtime into the scan,
without an automated browser (option C).

You export a HAR from your own browser session while using the target (DevTools
-> Network -> "Save all as HAR"). This module reads it and returns the request
URLs and query-parameter names it contains — including the XHR/fetch endpoints a
static crawl never sees.

Those URLs are not fetched here. They are returned so you can hand them to
`build_run_plan` as extra seeds: every one is then authorized, scope-filtered,
rate-limited, SSRF-checked, and audited by the normal pipeline. So HAR ingestion
widens discovery without adding a second, ungoverned egress path or any
dependency — the browser that produced the HAR was yours, not the scanner's.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Set
from urllib.parse import urlsplit, urlunsplit, parse_qsl


@dataclass
class HarResult:
    urls: List[str] = field(default_factory=list)          # unique request URLs, in order
    params: Set[str] = field(default_factory=set)          # query-param names seen
    methods: Dict[str, Set[str]] = field(default_factory=dict)  # url -> HTTP methods seen

    def summary(self) -> str:
        return f"urls={len(self.urls)} params={len(self.params)}"


def _normalize(url: str) -> str:
    try:
        s = urlsplit(url)
    except ValueError:
        return ""
    if s.scheme not in ("http", "https") or not s.netloc:
        return ""
    return urlunsplit((s.scheme, s.netloc, s.path or "/", s.query, ""))  # drop fragment


def parse_har(data) -> HarResult:
    """Parse a HAR (JSON string, bytes, or already-loaded dict) into a HarResult.
    Tolerant of malformed entries — a bad entry is skipped, not fatal."""
    if isinstance(data, (bytes, bytearray)):
        data = data.decode("utf-8", "replace")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError as e:
            raise ValueError(f"not valid HAR/JSON: {e}")
    if not isinstance(data, dict):
        raise ValueError("HAR root must be an object")

    entries = (data.get("log") or {}).get("entries")
    if not isinstance(entries, list):
        raise ValueError("HAR has no log.entries array")

    result = HarResult()
    seen: Dict[str, None] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request")
        if not isinstance(req, dict):
            continue
        url = _normalize(str(req.get("url") or ""))
        if not url:
            continue
        method = str(req.get("method") or "GET").upper()
        result.methods.setdefault(url, set()).add(method)
        if url not in seen:
            seen[url] = None
            result.urls.append(url)
        for k, _ in parse_qsl(urlsplit(url).query):
            result.params.add(k)
    return result


def har_seeds(data) -> List[str]:
    """Convenience: just the unique in-HAR URLs, ready to pass as extra seeds to
    build_run_plan (which authorizes and scope-filters them)."""
    return parse_har(data).urls
