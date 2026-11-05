#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Check, by dry run, that each make target installs only the pinned tools it
# runs on a fresh clone (no .tools/), and that every install line is the one
# `make tools` prints (same module, same pinned version). Guards against a
# target depending on the catch-all `tools` again (issue #26).
#
# Usage: scripts/check-tool-deps.sh [makefile]
#   makefile  Makefile to check (default: the repo's Makefile). It is copied to
#             a temp dir as `Makefile`, so `.tools/` never exists there.
set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
src=${1:-$root/Makefile}
[ -f "$src" ] || { echo "check-tool-deps: no such makefile: $src" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp "$src" "$tmp/Makefile"

all="actionlint gofumpt golangci-lint goreleaser govulncheck"

# Expected tool set per target ("-" means no go install line).
expected() {
  case "$1" in
    lint) echo "golangci-lint" ;;
    fmt) echo "gofumpt" ;;
    vuln) echo "govulncheck" ;;
    check-workflows) echo "actionlint" ;;
    check | ci) echo "actionlint golangci-lint" ;;
    pre-push) echo "golangci-lint govulncheck" ;;
    audit) echo "goreleaser govulncheck" ;;
    test) echo "-" ;;
    tools | bootstrap) echo "$all" ;;
  esac
}

fail() { echo "check-tool-deps: $*" >&2; exit 1; }

# Dry run of one target in the fresh-clone layout. Flags are unset so -k/-j and
# jobserver state from an outer make do not leak; GO and TOOLS_DIR are pinned on
# the command line so exported overrides cannot change the parse.
dry() {
  env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL -u MAKEFILES -u GNUMAKEFLAGS \
    make -n -C "$tmp" GO=go TOOLS_DIR=.tools "$1"
}

# Install lines only.
installs() { printf '%s\n' "$1" | grep ' go install ' || true; }

# Tool names from install lines: module path before @, minus /vN, last element.
tools_of() {
  local names
  names=$(printf '%s\n' "$1" | sed -n 's/.* go install \([^@ ]*\)@.*/\1/p' |
    sed 's#/v[0-9][0-9]*$##; s#.*/##' | sort -u | tr '\n' ' ')
  names=${names% }
  if [ -z "$names" ]; then echo "-"; else echo "$names"; fi
}

tools_out=$(dry tools) || fail "make -n tools failed"
pins=$(installs "$tools_out")

bad=0
for target in lint fmt vuln check-workflows check ci pre-push audit test tools bootstrap; do
  out=$(dry "$target") || fail "make -n $target failed"
  lines=$(installs "$out")
  got=$(tools_of "$lines")
  want=$(expected "$target")
  if [ "$got" != "$want" ]; then
    echo "check-tool-deps: make $target would install: $got; want: $want" >&2
    bad=1
  fi
  # Pin parity: each install line must be byte-identical to the `make tools` one.
  if [ -n "$lines" ]; then
    while IFS= read -r line; do
      if ! printf '%s\n' "$pins" | grep -qxF -- "$line"; then
        echo "check-tool-deps: make $target runs an install line that differs from make tools: $line" >&2
        bad=1
      fi
    done <<EOF2
$lines
EOF2
  fi
done

[ "$bad" -eq 0 ] || exit 1
echo "check-tool-deps: OK"
