#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Check that every third-party module linked into ward ships a licence file,
# so the goreleaser `before` hook (scripts/third-party-licenses.sh) cannot
# fail at tag time. Wired into `make check`, so a dependency without a licence
# is caught when it is added, not at release.
#
# Usage: scripts/check-third-party-licenses.sh
# 1. Self-test: a fake module whose dependency has no licence must fail;
#    the same module with a licence must pass and carry it.
# 2. Real run: generate into a temp dir for this repo and sanity-check it.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
gen="$here/third-party-licenses.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# The fake module lives outside the repo, where a version manager (mise, asdf)
# may not resolve `go`. Pin the repo's toolchain on PATH for every run below.
PATH="$(cd "$here/.." && go env GOROOT)/bin:$PATH"
export PATH

# --- self-test ---------------------------------------------------------------
mkdir -p "$T/app/cmd/app" "$T/app/dep"
cat >"$T/app/go.mod" <<'EOF'
module example.com/app

go 1.25.0

require example.com/dep v0.0.0

replace example.com/dep => ./dep
EOF
printf 'module example.com/dep\n\ngo 1.25.0\n' >"$T/app/dep/go.mod"
printf 'package dep\n\nfunc Hello() string { return "hi" }\n' >"$T/app/dep/dep.go"
printf 'package main\n\nimport "example.com/dep"\n\nfunc main() { println(dep.Hello()) }\n' >"$T/app/cmd/app/main.go"

if GOFLAGS=-mod=mod "$gen" "$T/out" "$T/app" ./cmd/app >"$T/log" 2>&1; then
  echo "check-third-party-licenses selftest: expected failure for a module with no licence" >&2
  exit 1
fi
grep -q 'example.com/dep: no LICENSE' "$T/log" || {
  echo "check-third-party-licenses selftest: unlicensed module not named in error:" >&2
  cat "$T/log" >&2
  exit 1
}
[[ ! -e "$T/out" ]] || { echo "check-third-party-licenses selftest: partial output left behind" >&2; exit 1; }

printf 'fake licence\n' >"$T/app/dep/LICENSE"
GOFLAGS=-mod=mod "$gen" "$T/out" "$T/app" ./cmd/app >"$T/log" 2>&1 || {
  echo "check-third-party-licenses selftest: licensed module should pass:" >&2
  cat "$T/log" >&2
  exit 1
}
for f in example.com/dep/LICENSE go-stdlib/LICENSE MODULES.txt; do
  [[ -f "$T/out/$f" ]] || { echo "check-third-party-licenses selftest: missing $f" >&2; exit 1; }
done
grep -q '^example.com/app ' "$T/out/MODULES.txt" && {
  echo "check-third-party-licenses selftest: main module listed as third-party" >&2
  exit 1
}

# --- real run ----------------------------------------------------------------
"$gen" "$T/real" >/dev/null
n="$(wc -l <"$T/real/MODULES.txt" | tr -d ' ')"
(( n >= 2 )) || { echo "check-third-party-licenses: only $n entries in MODULES.txt" >&2; exit 1; }
echo "check-third-party-licenses: OK ($n modules incl. Go standard library)"
