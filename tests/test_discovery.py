#!/usr/bin/env python3
"""Tests for discovery.py. Uses fake fetch results (no network). Run: python3 test_discovery.py."""
import sys
from dataclasses import dataclass, field
from typing import Dict

from horkos_sec.discovery import crawl, extract, CrawlResult


@dataclass
class Fake:
    ok: bool = True
    headers: Dict[str, str] = field(default_factory=lambda: {"content-type": "text/html"})
    body: bytes = b""
    final_url: str = ""


# ---- extract ---------------------------------------------------------------

def test_extract_links_params_forms():
    html = """
    <a href="/a?x=1&y=2">a</a>
    <a href="https://example.com/b">b</a>
    <a href="mailto:x@y.z">skip</a>
    <script src="/s.js"></script>
    <form action="/login" method="post">
       <input name="user"><input name="pass">
    </form>
    """
    urls, params, forms = extract(html, "https://example.com/")
    assert "https://example.com/a?x=1&y=2" in urls
    assert "https://example.com/b" in urls
    assert "https://example.com/s.js" in urls
    assert not any("mailto" in u for u in urls)
    assert params == {"x", "y"}
    assert len(forms) == 1 and forms[0].method == "post" and forms[0].fields == ["user", "pass"]


def test_extract_drops_fragment_and_nonhttp():
    urls, _, _ = extract('<a href="#top">t</a><a href="ftp://h/x">f</a><a href="/ok#frag">o</a>',
                         "https://example.com/")
    assert urls == {"https://example.com/ok"}


# ---- crawl -----------------------------------------------------------------

def _site(pages):
    """pages: {url: html}. Returns a fetch() over them."""
    def fetch(url):
        if url not in pages:
            return Fake(ok=False)
        return Fake(ok=True, body=pages[url].encode(), final_url=url)
    return fetch


def _scope_example(url):
    return "example.com" in url


def test_crawl_follows_in_scope_links():
    pages = {
        "https://example.com/": '<a href="/one">1</a><a href="/two?q=1">2</a>',
        "https://example.com/one": '<a href="/three">3</a>',
        "https://example.com/two": "no links",
        "https://example.com/three": "leaf",
    }
    res = crawl(["https://example.com/"], _site(pages), _scope_example, max_pages=50, max_depth=5)
    assert set(res.fetched) >= {"https://example.com/", "https://example.com/one"}
    assert "q" in res.params
    assert "https://example.com/three" in res.discovered


def test_crawl_stays_in_scope():
    pages = {"https://example.com/": '<a href="https://evil.test/x">e</a><a href="/ok">o</a>'}
    res = crawl(["https://example.com/"], _site(pages), _scope_example)
    assert "https://evil.test/x" in res.skipped_out_of_scope
    assert not any("evil.test" in u for u in res.fetched)


def test_crawl_respects_max_pages():
    pages = {f"https://example.com/{i}": f'<a href="/{i+1}">n</a>' for i in range(20)}
    pages["https://example.com/"] = '<a href="/0">s</a>'
    res = crawl(["https://example.com/"], _site(pages), _scope_example, max_pages=5, max_depth=99)
    assert len(res.fetched) == 5


def test_crawl_respects_max_depth():
    pages = {
        "https://example.com/": '<a href="/d1">1</a>',
        "https://example.com/d1": '<a href="/d2">2</a>',
        "https://example.com/d2": '<a href="/d3">3</a>',
    }
    res = crawl(["https://example.com/"], _site(pages), _scope_example, max_depth=1)
    assert "https://example.com/d1" in res.fetched
    assert "https://example.com/d2" not in res.fetched   # depth 2 > max_depth 1


def test_crawl_skips_out_of_scope_seed():
    res = crawl(["https://evil.test/"], _site({}), _scope_example)
    assert res.fetched == [] and "https://evil.test/" in res.skipped_out_of_scope


def test_crawl_ignores_non_html_body():
    def fetch(url):
        return Fake(ok=True, headers={"content-type": "application/json"},
                    body=b'{"href":"/should-not-parse"}', final_url=url)
    res = crawl(["https://example.com/"], fetch, _scope_example)
    assert res.fetched == ["https://example.com/"]
    assert res.discovered == {"https://example.com/"}   # nothing extracted from JSON


def _main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    n = 0
    for t in tests:
        t(); n += 1; print(f"ok {n} {t.__name__}")
    print(f"RESULT: {n}/{len(tests)} passed")
    sys.exit(0 if n == len(tests) else 1)


if __name__ == "__main__":
    _main()
