# scrubber

Redacts sensitive identifiers from a source tree before any of it is open-sourced. It reads a private tree and writes a **scrubbed copy** to a separate directory — it never edits in place — and emits a report of every redaction and every refused file.

## Why it's split in two

- **The tool is public.** Generic structural patterns (RFC1918 IPs, emails, private-key blocks, cloud tokens) live in [`rules.json`](rules.json) and are safe to publish.
- **The secret list is not.** Exact strings — real hostnames, program slugs, operator IDs, internal paths — go in a **local denylist file that is gitignored and never committed**. You pass it with `--denylist`. This way the scrubber can't itself leak what it scrubs.

## Fail-closed behaviour

- `block_globs` in `rules.json` name paths that must **never** be published (`keys/`, `ledger/`, `identities/`, `policies/`, `scopes/`, `docs/`, `*.key`, `*vault*`, …). Matching files are **not copied, not scrubbed, not even read** — they're listed as *refused* and force exit 1.
- After scrubbing, a **double-check pass** re-scans the output for high-risk patterns (`verify: true`). Any survivor is reported as *residual* and forces exit 1.
- A missing `--denylist` file is a hard error (exit 2), not a silent pass. Omitting `--denylist` entirely runs generic patterns only and prints a warning — use it for a first look, never for the real export.

## Usage

```bash
python3 scrub.py \
  --src  /path/to/private-tree \
  --out  /path/to/scrubbed-copy \
  --denylist /path/to/local-denylist.txt \
  --force          # overwrite a non-empty --out
```

Exit: `0` clean · `1` refused files or residual hits (read the report) · `2` usage/config error.

Outputs land in `--out`:
- the scrubbed copy of every allowed file
- `scrub-report.json` — machine-readable: summary, refused, residual, per-redaction
- `scrub-report.md` — human-readable: refused list, residual list, redactions by file

## Denylist format

One entry per line; `#` comments and blanks ignored.

```
secret-host.example        # → [REDACTED]
some-internal-host  => [REDACTED_HOST]
program-slug        => [PROGRAM]
```

Matching is case-insensitive and literal (not regex). List the plain string; all casings are caught.

## Recommended flow

1. Dry-run with `--denylist` pointed at your local list, `--out` **outside any git repo**.
2. Read `scrub-report.md`: confirm the *refused* list is what you expect gone, and *residual* is empty.
3. Independently grep the `--out` tree for your known secrets as a second pair of eyes.
4. Only then copy the vetted files into the public repo.

Never commit the denylist or the raw `--out` tree; commit only the files you've reviewed.
