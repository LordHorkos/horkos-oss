# Verification

## Full suite (CI)

rbenv's own test suite (bats v1.10.0, `test/run`, as in rbenv's CI) run on a patched `master` checkout by this repo's [Upstream fixes](../../.github/workflows/upstream-fixes.yml) workflow:

| Runner | bash | Tests | Result | ShellCheck |
|---|---|---|---|---|
| ubuntu-latest | 5.3.9 | 182 | 182 pass | clean |
| macos-latest | 3.2.57 (default on the runner) | 182 | 182 pass | — |
| macos-latest, forced `/bin/bash` | 3.2.57 | 182 | 182 pass | — |

The workflow re-runs weekly against current rbenv `master` to catch drift.

## Bug caught by the macOS job

An intermediate version of the fix re-read the remainder of the line with `read -d "" -r version _ <<<"$rest"` when the BOM was followed by whitespace. It passed on bash 5 but failed `ignores a UTF-8 byte order mark followed by blank lines` on bash 3.2. Diagnosis on the macOS runner:

```
input:            EF BB BF \r \n \r \n ' ' ' ' 3.3.0 \r \n
bash 3.2 $rest:   "\r\n  3.3.0\r"     (bash 5 strips the leading "\r\n  ")
read <<<"$rest":  ""                  (exit 1)
for w in $rest:   first field ""      ("\r" is a non-whitespace IFS character)
```

The final fix iterates over `$rest` and takes the first non-empty word (globbing disabled with `set -f`).

## Script-level edge cases (bash 5.2, Linux)

| Input file | Expected | Result |
|---|---|---|
| BOM + `3.3.0` + CRLF | `3.3.0` | pass |
| BOM + CRLF blank lines + `  3.3.0` | `3.3.0` | pass |
| BOM + LF blank lines + `3.3.0` | `3.3.0` | pass |
| BOM + `  3.3.0 x` | `3.3.0` | pass |
| BOM + blank line + `../foo` | rejected | rejected |
| BOM + blank line + `*` | literal `*` (no glob expansion) | pass |
| BOM + blank lines only | exit 1 | exit 1 |
| `3.3.0` (no BOM) | `3.3.0` | pass |

The original one-line fix (`version="${version#$'\xef\xbb\xbf'}"`) returned an empty version for every "BOM followed by whitespace" case above.
