# rbenv: `.ruby-version` with a UTF-8 BOM is not read correctly

**Project:** [rbenv](https://github.com/rbenv/rbenv) · **Affects:** 1.3.2 and `master` at `07e9b1e` · **Status:** submitted upstream as [rbenv#1665](https://github.com/rbenv/rbenv/pull/1665)

## Symptom

Some Windows editors (Notepad, PowerShell `Out-File`) save files with a UTF-8 byte order mark. rbenv then reports an installed version as missing, with an invisible prefix in the error:

```
$ printf '\xef\xbb\xbf3.3.0\r\n' > .ruby-version   # 3.3.0 is installed
$ rbenv version-name
rbenv: version `﻿3.3.0' is not installed (set by /tmp/proj/.ruby-version)
```

rbenv already strips `\r` for Windows line endings. The BOM is the remaining Windows encoding artifact it does not handle.

## Root cause

`libexec/rbenv-version-file-read` reads the first word with `read`, splitting on `IFS` plus `\r`. The BOM bytes `EF BB BF` are not whitespace, so they stay attached to the version string and the lookup of `versions/<BOM>3.3.0` fails.

## Fix

Strip a leading BOM after `read` and before the `..` / path-segment checks, so those checks still validate the cleaned value. If the BOM is followed by whitespace, take the next word, matching rbenv's existing handling of leading spaces and blank lines.

```bash
read -n 1024 -d "" -r version rest <"$VERSION_FILE" || :
bom=$'\xef\xbb\xbf'
if [[ $version == "$bom"* ]]; then
  version="${version#"$bom"}"
  if [ -z "$version" ]; then
    set -f
    for version in $rest; do
      [ -z "$version" ] || break
    done
    set +f
  fi
fi
```

The BOM is held in a variable and quoted in the expansion for portability to bash 3.2 (macOS). The fallback takes the first **non-empty** word: on bash 3.2, when the BOM is followed by CRLF blank lines, `$rest` keeps a leading `\r` (a non-whitespace `IFS` character), so plain word splitting yields an empty first field. bash 5 strips it. This was caught by the macOS bash 3.2 CI job in this repo; an intermediate version that re-read `$rest` with `read` passed on bash 5 but failed on 3.2.

An earlier one-line version (`version="${version#$'\xef\xbb\xbf'}"`) missed the case where the BOM is followed by spaces or blank lines: the version came back empty and rbenv exited 1 with no message.

The patch adds three regression tests to `test/version-file-read.bats`.

## Files

- [`fix.patch`](fix.patch) — `git am`-ready commit against rbenv `master`
- [`tests.md`](tests.md) — verification results

## Apply

```bash
git clone https://github.com/rbenv/rbenv && cd rbenv
git am /path/to/fix.patch
bats test/version-file-read.bats
```
