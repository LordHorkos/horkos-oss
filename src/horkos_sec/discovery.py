"""
Passive discovery — expand seeds into in-scope URLs, parameters, and form
targets by crawling, observe-only.

The crawler fetches pages with an injected `fetch` callable (the guarded HTTP
client's GET), extracts links/params/forms from returned HTML, and only ever
enqueues or follows URLs an injected `in_scope` predicate accepts. It never
submits a form, never issues anything but the GET the fetcher performs, and
caps both breadth (max_pages) and depth (max_depth).

It produces data for later layers (detectors, reporting) to consume — it does
not judge or probe. "Passive" here means: read what the site serves to a normal
GET and follow in-scope links; nothing is mutated or injected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlsplit, parse_qsl, urlunsplit

# Attributes that carry a URL we may want to discover (not fetch indiscriminately).
_URL_ATTRS = {
    "a": "href", "link": "href", "area": "href",
    "script": "src", "img": "src", "iframe": "src", "form": "action",
}


@dataclass
class Form:
    action: str
    method: str
    fields: List[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    fetched: List[str] = field(default_factory=list)          # URLs actually fetched
    discovered: Set[str] = field(default_factory=set)         # all in-scope URLs seen
    params: Set[str] = field(default_factory=set)             # query param names seen
    forms: List[Form] = field(default_factory=list)
    skipped_out_of_scope: Set[str] = field(default_factory=set)

    def summary(self) -> str:
        return (f"fetched={len(self.fetched)} discovered={len(self.discovered)} "
                f"params={len(self.params)} forms={len(self.forms)} "
                f"skipped_oos={len(self.skipped_out_of_scope)}")


class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls: List[str] = []
        self.forms: List[Form] = []
        self._form: Optional[Form] = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        attr = _URL_ATTRS.get(tag)
        if attr and a.get(attr):
            self.urls.append(a[attr])
        if tag == "form":
            self._form = Form(action=a.get("action", ""), method=(a.get("method") or "get").lower())
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea") and self._form is not None:
            name = a.get("name")
            if name:
                self._form.fields.append(name)

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def extract(html: str, base_url: str) -> Tuple[Set[str], Set[str], List[Form]]:
    """Return (absolute_urls, query_param_names, forms) found in `html`."""
    p = _LinkExtractor()
    try:
        p.feed(html)
    except Exception:
        pass  # malformed HTML: keep whatever was parsed before the error
    urls: Set[str] = set()
    params: Set[str] = set()
    for raw in p.urls:
        if raw.startswith(("mailto:", "javascript:", "tel:", "data:", "#")):
            continue
        absu = _normalize(urljoin(base_url, raw))
        if absu:
            urls.add(absu)
            params.update(k for k, _ in parse_qsl(urlsplit(absu).query))
    forms = [Form(_normalize(urljoin(base_url, f.action)) or base_url, f.method, f.fields)
             for f in p.forms]
    return urls, params, forms


def _normalize(url: str) -> str:
    try:
        s = urlsplit(url)
    except ValueError:
        return ""
    if s.scheme not in ("http", "https") or not s.netloc:
        return ""
    return urlunsplit((s.scheme, s.netloc, s.path or "/", s.query, ""))  # drop fragment


def _is_html(fetch_result) -> bool:
    ct = ""
    headers = getattr(fetch_result, "headers", {}) or {}
    ct = headers.get("content-type", "")
    return "html" in ct.lower()


def crawl(seeds, fetch: Callable, in_scope: Callable[[str], bool],
          max_pages: int = 50, max_depth: int = 3) -> CrawlResult:
    """
    Breadth-first, scope-gated crawl.

    fetch(url) -> an object with .ok, .headers, .body (bytes), .final_url
                  (e.g. GuardedHTTPClient.fetch).
    in_scope(url) -> bool. Only in-scope URLs are fetched or enqueued.
    """
    result = CrawlResult()
    visited: Set[str] = set()
    frontier: List[Tuple[str, int]] = []

    for s in seeds:
        n = _normalize(s)
        if not n:
            continue
        if in_scope(n):
            frontier.append((n, 0))
            result.discovered.add(n)
        else:
            result.skipped_out_of_scope.add(n)

    while frontier and len(result.fetched) < max_pages:
        url, depth = frontier.pop(0)
        if url in visited:
            continue
        visited.add(url)

        r = fetch(url)
        if not getattr(r, "ok", False):
            continue
        result.fetched.append(url)

        if not _is_html(r):
            continue
        try:
            body = (r.body or b"").decode("utf-8", "replace")
        except Exception:
            continue
        base = getattr(r, "final_url", None) or url
        urls, params, forms = extract(body, base)
        result.params.update(params)
        result.forms.extend(forms)

        for u in urls:
            if in_scope(u):
                result.discovered.add(u)
                if depth + 1 <= max_depth and u not in visited:
                    frontier.append((u, depth + 1))
            else:
                result.skipped_out_of_scope.add(u)

    return result
