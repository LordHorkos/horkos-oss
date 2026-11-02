# Verification

## Script-level results (bash 5.2, Linux)

The patched `rbenv-version-file-read` was run directly against fixture files, comparing the original one-line fix (v1) with this fix (v2).

| Input file | Expected | v1 | v2 |
|---|---|---|---|
| BOM + `3.3.0` + CRLF | `3.3.0` | pass | pass |
| BOM + blank lines + `  3.3.0` | `3.3.0` | **exit 1, empty** | pass |
| BOM + `  3.3.0` | `3.3.0` | **exit 1, empty** | pass |
| BOM + `../foo` | rejected | rejected | rejected |
| BOM + `..` | rejected | rejected | rejected |
| BOM only | exit 1 | exit 1 | exit 1 |
| `3.3.0` (no BOM) | `3.3.0` | pass | pass |
| blank line + `  1.9.3 x` | `1.9.3` | pass | pass |
| BOM + `3.3.0`, `LC_ALL=C` | `3.3.0` | pass | pass |

## Full suite

With the v1 fix, `bats test` ran 180 tests and 179 passed. The one failure, `non-writable shims directory` (`rehash.bats`), fails identically on unpatched `master` in that environment. That test expects a write to a read-only directory to fail; the most likely cause is that the suite ran as root, for whom such writes succeed.

## Pending

- Full `bats` suite with the v2 fix
- bash 3.2 (macOS) run

Both will be covered by rbenv's CI (macOS and Ubuntu) on [rbenv#1665](https://github.com/rbenv/rbenv/pull/1665).
