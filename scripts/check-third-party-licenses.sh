#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Check that every third-party module linked into ward ships a licence file,
# so the goreleaser `before` hook (scripts/third-party-licenses.sh) cannot
# fail at tag time. Wired into `make check`, so a dependency without a licence
# is caught when it is added, not at release.
#
# Usage: scripts/check-third-party-licenses.sh
# 1. Self-test: a fake module whose dependency has no licence, or only a
#    NOTICE, must fail; the same module with a licence must pass and carry it;
#    an existing out-dir that is not a previous output must be refused intact;
#    the goreleaser-matrix parser must catch a drifted target list.
# 2. Targets: the generator's TARGETS must equal the goos x goarch matrix
#    (minus ignore) in .goreleaser.yaml.
# 3. Real run: generate into a temp dir for this repo and sanity-check it.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
gen="$here/third-party-licenses.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# The fake module lives outside the repo, where a version manager (mise, asdf)
# may not resolve `go`. Pin the repo's toolchain on PATH for every run below.
PATH="$(cd "$here/.." && go env GOROOT)/bin:$PATH"
export PATH

fail() { echo "check-third-party-licenses: $*" >&2; exit 1; }

# goreleaser_targets <file>: goos/goarch pairs of the builds matrix, minus
# ignore entries, sorted. Plain awk over the block-list layout that
# .goreleaser.yaml uses (goos:, goarch:, ignore:), so there is no yq dependency.
goreleaser_targets() {
  awk '
    function val(line) { sub(/^[^:]*:[ \t]*/, "", line); gsub(/["\047 \t]/, "", line); return line }
    function item(line) { sub(/^[ \t]*-[ \t]*/, "", line); gsub(/["\047 \t]/, "", line); return line }
    # ln, not the bare record variable: check-public reads "space dollar digit" as a price.
    {ln=$0}
    /^[^ #]/ { section = ln; mode = ""; next }
    section !~ /^builds:/ { next }
    /^[ \t]*goos:[ \t]*$/   { mode = "goos"; next }
    /^[ \t]*goarch:[ \t]*$/ { mode = "goarch"; next }
    /^[ \t]*ignore:[ \t]*$/ { mode = "ignore"; next }
    mode == "ignore" && /^[ \t]*-[ \t]*goos:/ { ig_os = val(ln); next }
    mode == "ignore" && /^[ \t]*goarch:/      { ignored[ig_os "/" val(ln)] = 1; next }
    mode == "goos"   && /^[ \t]*-[ \t]/ { os[item(ln)] = 1; next }
    mode == "goarch" && /^[ \t]*-[ \t]/ { arch[item(ln)] = 1; next }
    /^[ \t]*(-[ \t]*)?[a-z_]+:/ { mode = "" }
    END { for (o in os) for (a in arch) if (!((o "/" a) in ignored)) print o "/" a }
  ' "$1" | sort
}

# --- self-test: matrix parser --------------------------------------------------
cat >"$T/gr.yaml" <<'YAML'
builds:
  - id: x
    main: ./cmd/x
    goos:
      - darwin
      - linux
      - freebsd
    goarch:
      - amd64
      - arm64
    ignore:
      - goos: darwin
        goarch: amd64
archives:
  - id: x
    files:
      - LICENSE*
YAML
want=$'darwin/arm64\nfreebsd/amd64\nfreebsd/arm64\nlinux/amd64\nlinux/arm64'
got="$(goreleaser_targets "$T/gr.yaml")"
[[ "$got" == "$want" ]] || fail "selftest: matrix parser gave: $(echo $got)"
[[ "$got" != "$("$gen" --print-targets | sort)" ]] || fail "selftest: drifted matrix not detected"

# --- self-test: generator ------------------------------------------------------
mkdir -p "$T/app/cmd/app" "$T/app/dep"
cat >"$T/app/go.mod" <<'GOMOD'
module example.com/app

go 1.25.0

require example.com/dep v0.0.0

replace example.com/dep => ./dep
GOMOD
printf 'module example.com/dep\n\ngo 1.25.0\n' >"$T/app/dep/go.mod"
printf 'package dep\n\nfunc Hello() string { return "hi" }\n' >"$T/app/dep/dep.go"
printf 'package main\n\nimport "example.com/dep"\n\nfunc main() { println(dep.Hello()) }\n' >"$T/app/cmd/app/main.go"
run_fake() { GOFLAGS=-mod=mod "$gen" "$1" "$T/app" ./cmd/app >"$T/log" 2>&1; }

# No licence file at all.
if run_fake "$T/out"; then fail "selftest: expected failure for a module with no licence"; fi
grep -q 'example.com/dep: no LICENSE' "$T/log" || { cat "$T/log" >&2; fail "selftest: unlicensed module not named in error"; }
[[ ! -e "$T/out" ]] || fail "selftest: partial output left behind"

# NOTICE only.
printf 'fake notice\n' >"$T/app/dep/NOTICE"
if run_fake "$T/out"; then fail "selftest: expected failure for a NOTICE-only module"; fi
grep -q 'example.com/dep.*only NOTICE/PATENTS' "$T/log" || { cat "$T/log" >&2; fail "selftest: NOTICE-only module not reported"; }
[[ ! -e "$T/out" ]] || fail "selftest: partial output left behind (NOTICE-only)"

# An existing directory that is not a previous output is refused and kept.
mkdir -p "$T/keep" && printf 'precious\n' >"$T/keep/file"
printf 'fake licence\n' >"$T/app/dep/LICENSE"
if run_fake "$T/keep"; then fail "selftest: expected refusal of a non-output directory"; fi
[[ -f "$T/keep/file" ]] || fail "selftest: non-output directory was deleted"

# Licensed: passes and carries LICENSE + NOTICE.
run_fake "$T/out" || { cat "$T/log" >&2; fail "selftest: licensed module should pass"; }
for f in example.com/dep/LICENSE example.com/dep/NOTICE go-stdlib/LICENSE MODULES.txt; do
  [[ -f "$T/out/$f" ]] || fail "selftest: missing $f"
done
if grep -q '^example.com/app ' "$T/out/MODULES.txt"; then fail "selftest: main module listed as third-party"; fi

# A previous output regenerates in place; a relative path is the caller's cwd.
(cd "$T" && run_fake out) || { cat "$T/log" >&2; fail "selftest: regenerating a previous output should pass"; }
[[ -f "$T/out/example.com/dep/LICENSE" ]] || fail "selftest: relative out-dir not resolved against the caller's cwd"

# --- targets -------------------------------------------------------------------
gr="$(goreleaser_targets "$here/../.goreleaser.yaml")"
tg="$("$gen" --print-targets | sort)"
[[ -n "$gr" && "$gr" == "$tg" ]] ||
  fail "TARGETS in scripts/third-party-licenses.sh ($(echo $tg)) differ from the .goreleaser.yaml build matrix ($(echo $gr)) — remediation: make them equal"

# --- real run ------------------------------------------------------------------
"$gen" "$T/real" >/dev/null
grep -q '^gopkg.in/yaml.v3 ' "$T/real/MODULES.txt" || fail "direct dependency gopkg.in/yaml.v3 missing from MODULES.txt"
n="$(wc -l <"$T/real/MODULES.txt" | tr -d ' ')"
echo "check-third-party-licenses: OK ($n modules incl. Go standard library; targets match .goreleaser.yaml)"
