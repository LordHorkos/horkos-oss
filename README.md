# horkos-oss

Open-source security work by **HORKOS** — fixes, tools, and research released publicly.

## Contents

| Path | What it is | Status |
|---|---|---|
| [`upstream-fixes/rbenv-utf8-bom`](upstream-fixes/rbenv-utf8-bom) | rbenv fails to read a `.ruby-version` file saved with a UTF-8 byte order mark | Submitted upstream: [rbenv#1665](https://github.com/rbenv/rbenv/pull/1665) |
| [`lib/severity-band`](lib/severity-band) | Cap findings into a restricted severity band without silently dropping high/critical results | Released |
| [`tools/scrubber`](tools/scrubber) | Redact a source tree before open-sourcing it | Released |

## Layout

- `upstream-fixes/` — bugs found in third-party open-source projects, each with a root-cause write-up, a patch that applies to upstream, and verification results.
  - Each fix has `upstream.conf` (repo + ref) and `ci.sh`. The [Upstream fixes](.github/workflows/upstream-fixes.yml) workflow clones upstream, applies the patch, and runs the project's own test suite on Ubuntu, macOS, and macOS with the system bash 3.2. It re-runs weekly to catch upstream drift.

All pushes are scanned for leaked secrets by [gitleaks](.github/workflows/secret-scan.yml).

## Reporting

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Patches under `upstream-fixes/` are offered to their upstream projects under those projects' own licenses.
