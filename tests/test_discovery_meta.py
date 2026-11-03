#!/usr/bin/env python3
"""Phase 3 tests: robots/sitemap ingestion + provenance. Run: python3 test_discovery_meta.py."""
import sys
from dataclasses import dataclass, field
from typing import Dict

from horkos_sec.discovery import crawl, parse_robots, parse_sitemap


@dataclass
class Fake:
    ok: bool = True
    headers: Dict[str, str] = field(default_factory=lambda: {"content-type": "text/html"})
    body: bytes = b""
    final_url: str = ""


def _scope(url):
    return "example.com" in url


# ---- parsers ---------------------------------------------------------------

def test_parse_robots_paths_and_sitemaps():
    txt = ("User-agent: *\nDisallow: /admin/\nAllow: /public\n"
           "Disallow: /\nSitemap: https://example.com/sitemap.xml\n")
    urls, sitemaps = parse_robots(txt, "https://example.com")
    assert "https://example.com/admin/" in urls
    assert "https://example.com/public" in urls
    assert "https://example.com/sitemap.xml" in sitemaps
    assert "https://example.com/" not in urls          # bare "/" skipped


def test_parse_sitemap_locs():
    xml = ("<urlset><url><loc>https://example.com/a</loc></url>"
           "<url><loc>https://example.com/b</loc></url></urlset>")
    locs = parse_sitemap(xml, "https://example.com")
    assert locs == {"https://example.com/a", "https://example.com/b"}


# ---- integration -----------------------------------------------------------

def _site(pages):
    def fetch(url):
        if url not in pages:
            return Fake(ok=False)
        ct = "application/xml" if url.endswith(".xml") else ("text/plain" if url.endswith(".txt") else "text/html")
        return Fake(ok=True, headers={"content-type": ct}, body=pages[url].encode(), final_url=url)
    return fetch


def test_crawl_ingests_robots_and_sitemap():
    pages = {
        "https://example.com/": "<a href='/linked'>l</a>",
        "https://example.com/linked": "leaf",
        "https://example.com/robots.txt":
            "Disallow: /from-robots\nSitemap: https://example.com/sitemap.xml\n",
        "https://example.com/sitemap.xml":
            "<urlset><url><loc>https://example.com/from-sitemap</loc></url></urlset>",
        "https://example.com/from-robots": "r",
        "https://example.com/from-sitemap": "s",
    }
    res = crawl(["https://example.com/"], _site(pages), _scope,
                max_pages=50, max_depth=3, discover_meta=True)
    assert "https://example.com/from-robots" in res.discovered
    assert "https://example.com/from-sitemap" in res.discovered
    assert "https://example.com/from-robots" in res.fetched
    assert res.provenance["https://example.com/"] == "seed"
    assert res.provenance["https://example.com/from-robots"] == "robots"
    assert res.provenance["https://example.com/from-sitemap"] == "sitemap"
    assert res.provenance["https://example.com/linked"] == "https://example.com/"


def test_meta_respects_scope():
    pages = {
        "https://example.com/": "x",
        "https://example.com/robots.txt":
            "Sitemap: https://evil.test/sitemap.xml\nDisallow: /ok\n",
    }
    res = crawl(["https://example.com/"], _site(pages), _scope, discover_meta=True)
    assert "https://evil.test/sitemap.xml" in res.skipped_out_of_scope
    assert not any("evil.test" in u for u in res.fetched)


def test_discover_meta_off():
    pages = {"https://example.com/": "x",
             "https://example.com/robots.txt": "Disallow: /secret\n",
             "https://example.com/secret": "s"}
    res = crawl(["https://example.com/"], _site(pages), _scope, discover_meta=False)
    assert "https://example.com/secret" not in res.discovered


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
