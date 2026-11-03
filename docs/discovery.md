# discovery

Passive, scope-gated crawling: expand seed URLs into the in-scope URLs,
parameter names, and form targets a site exposes to a normal `GET`. It never
submits a form or sends anything but the GET the injected fetcher performs, and
it only enqueues or follows URLs the injected scope predicate accepts.

Decoupled by design: `crawl` takes a `fetch` callable and an `in_scope` callable,
so it drops onto the guarded HTTP client without importing it.

## Usage

```python
from functools import partial
from horkos_sec import crawl, check_scope
# `client` is a GuardedHTTPClient wired for the engagement (see controller docs)

scope = engagement.scope
result = crawl(
    seeds=["https://example.com/"],
    fetch=client.fetch,                           # GET-only, guarded, pinned, audited
    in_scope=lambda u: check_scope(u, scope).in_scope,
    max_pages=50,
    max_depth=3,
)

print(result.summary())      # fetched=.. discovered=.. params=.. forms=.. skipped_oos=..
result.discovered            # all in-scope URLs seen
result.params                # query parameter names (feed to later detectors)
result.forms                 # Form(action, method, fields) — recorded, never submitted
result.skipped_out_of_scope  # links that were seen but not followed
```

`extract(html, base_url)` is also exposed standalone → `(urls, param_names, forms)`.

## Behaviour

- **robots.txt + sitemap.xml** (`discover_meta=True`, default): before crawling,
  it pulls in-scope URLs from each seed host's `robots.txt` (Disallow/Allow paths
  and `Sitemap:` entries) and `sitemap.xml` (`<loc>` URLs, parsed by regex — no
  XML parser, so no XXE on an untrusted sitemap). Out-of-scope entries are
  skipped.
- **Provenance**: `result.provenance[url]` records where each URL was found —
  `"seed"`, `"robots"`, `"sitemap"`, or the parent page URL.
- **Breadth-first**, capped by `max_pages` (fetches) and `max_depth` (link hops).
- **In-scope only**: seeds and discovered links are checked with `in_scope`;
  anything else goes to `skipped_out_of_scope`, never fetched.
- **HTML only**: non-HTML responses (JSON, binaries) are fetched once but not
  parsed for links.
- **Redirect-aware**: extraction uses the fetcher's `final_url` as the base.
- `mailto:`/`javascript:`/`tel:`/`data:`/fragment links are ignored; fragments
  are stripped so `/p#a` and `/p#b` aren't treated as two URLs.

Because every fetch goes through the guarded client, the request budget, rate
limit, SSRF-safe resolution, and audit log all still apply — discovery can't
exceed the run's caps or reach out of scope.

## Tests

```bash
python3 tests/test_discovery.py     # or: python -m pytest
```
