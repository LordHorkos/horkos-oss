#!/usr/bin/env bash
# Runs inside a patched rbenv checkout. Mirrors rbenv's own CI
# (.github/workflows/ci.yml: bats v1.10.0 + test/run) and adds ShellCheck
# on the changed script where it is available.
set -euo pipefail

if command -v shellcheck >/dev/null 2>&1; then
  echo "== shellcheck libexec/rbenv-version-file-read"
  shellcheck libexec/rbenv-version-file-read
fi

echo "== bats (rbenv full suite)"
git clone -q --depth 1 --branch v1.10.0 https://github.com/bats-core/bats-core.git bats
PATH="$PWD/bats/bin:$PATH" test/run
