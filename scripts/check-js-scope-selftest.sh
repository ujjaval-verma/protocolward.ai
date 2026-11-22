#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Self-test for check-js-scope.sh: a green baseline, 11 one-file violation cases, the scope argument and the exit-2 cases.
# The check always runs under "$BASH" (the interpreter running this file), never via its shebang,
# so a bash 3.2 run really exercises the check under bash 3.2.
set -euo pipefail
export LC_ALL=C
here="$(cd "$(dirname "$0")" && pwd)"
# Resolve an absolute go before leaving the repo: version-manager shims fail outside it.
GO="$(cd "$here/.." && "${GO:-go}" env GOROOT)/bin/go"
export GO
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fail() { echo "check-js-scope selftest: $*" >&2; exit 1; }
run() { "$BASH" "$here/check-js-scope.sh" "$@"; }

# put <root> <relpath> <content...>: write a file, one content line per argument.
put() {
  local root="$1" rel="$2"
  shift 2
  mkdir -p "$root/$(dirname "$rel")"
  printf '%s\n' "$@" > "$root/$rel"
}

base="$T/base"
put "$base" go.mod 'module example.test/m' '' 'go 1.22'
put "$base" cmd/wardwasm/main_js.go '//go:build js && wasm' '' 'package main' '' 'func main() {}'
put "$base" cmd/wardwasm/internal/x/x_js.go 'package x'
put "$base" internal/p/p.go 'package p'
put "$base" internal/p/t.go '//go:build js || linux' '' 'package p'
put "$base" internal/p/s.go '//go:build js || darwin' '' 'package p'
put "$base" internal/p/u.go '//go:build ignore' '' 'package p'
put "$base" internal/p/v.go '//go:build wasip1' '' 'package p'
put "$base" internal/p/p_linux.go 'package p'
put "$base" internal/p/testdata/w_js.go 'package w'
put "$base" _skip/y_js.go 'package y'
mkdir "$T/nomod"

hint='check-js-scope: hint: move the file into the js/wasm lint scope, or add its package to WASM_PKG in the Makefile so make lint and make wasm-check cover it'
scope='./cmd/wardwasm/...'
ok2='check-js-scope: OK (2 js-only Go file(s), all in scope)'

# Baseline: without a green unmodified fixture, a red case proves nothing.
rc=0
out="$(run -C "$base" "$scope" 2>&1)" || rc=$?
if [ "$rc" -ne 0 ] || [ "$out" != "$ok2" ]; then
  fail "baseline: want exit 0 and exactly '$ok2'; got rc=$rc:"$'\n'"$out"
fi

# Base files that no violation case may name (full module-relative paths).
base_files="$(cd "$base" && find . -type f | sed 's|^\./||' | sort)"

# case <name> <relfile> <pkgdir-as-printed> <content...>
violation() {
  local name="$1" rel="$2" pkg="$3"
  shift 3
  local d="$T/case-$name" rc=0 out want f
  cp -R "$base" "$d"
  put "$d" "$rel" "$@"
  out="$(run -C "$d" "$scope" 2>&1)" || rc=$?
  [ "$rc" -eq 1 ] || fail "$name: want exit 1, got $rc:"$'\n'"$out"
  want="check-js-scope: $rel: compiled for js/wasm but for neither lint host (linux/amd64, darwin/arm64); package $pkg is outside the js/wasm lint scope ($scope)"
  [ "$(grep -cF ': compiled for js/wasm' <<<"$out")" -eq 1 ] || fail "$name: want exactly one violation line:"$'\n'"$out"
  grep -qxF "$want" <<<"$out" || fail "$name: missing line '$want':"$'\n'"$out"
  grep -qxF "$hint" <<<"$out" || fail "$name: missing hint line:"$'\n'"$out"
  if grep -q 'OK' <<<"$out"; then fail "$name: printed OK:"$'\n'"$out"; fi
  while IFS= read -r f; do
    if grep -qF "$f" <<<"$out"; then fail "$name: names base file $f:"$'\n'"$out"; fi
  done <<<"$base_files"
}

violation build-js internal/p/a.go internal/p '//go:build js' '' 'package p'
violation suffix-js internal/p/b_js.go internal/p 'package p'
violation suffix-wasm internal/p/c_wasm.go internal/p 'package p'
violation build-wasm internal/p/d.go internal/p '//go:build wasm' '' 'package p'
violation exclusions internal/p/e.go internal/p '//go:build !linux && !darwin' '' 'package p'
violation plus-build internal/p/l.go internal/p '// +build js' '' 'package p'
violation test-file internal/p/f_js_test.go internal/p 'package p'
violation xtest internal/p/g_test.go internal/p '//go:build js' '' 'package p_test'
violation neighbour cmd/wardwasmx/h.go cmd/wardwasmx '//go:build js' '' 'package h'
violation whole-package internal/onlyjs/o_js.go internal/onlyjs 'package onlyjs'
violation root-package k_js.go . 'package k'

# Scope comes from the arguments.
rc=0
out="$(run -C "$T/case-whole-package" "$scope" ./internal/onlyjs 2>&1)" || rc=$?
want='check-js-scope: OK (3 js-only Go file(s), all in scope)'
if [ "$rc" -ne 0 ] || [ "$out" != "$want" ]; then
  fail "scope-arg: want exit 0 and exactly '$want'; got rc=$rc:"$'\n'"$out"
fi

# A host package importing a package excluded under js/wasm must not make the gate fail (go list -e).
d="$T/case-host-only-import"
cp -R "$base" "$d"
put "$d" internal/hostonly/h.go '//go:build linux || darwin' '' 'package hostonly'
put "$d" internal/p/imp.go 'package p' '' 'import _ "example.test/m/internal/hostonly"'
rc=0
out="$(run -C "$d" "$scope" 2>&1)" || rc=$?
if [ "$rc" -ne 0 ] || [ "$out" != "$ok2" ]; then
  fail "host-only-import: want exit 0 and exactly '$ok2'; got rc=$rc:"$'\n'"$out"
fi

# Toolchain knobs: the verdict must not depend on the caller's GOFLAGS/GOEXPERIMENT/GOAMD64/GOARM64.
# Each decoy builds for js/wasm but for neither host only when the knob is at its default, so it must be flagged.
# An exported variable is overridden by the script (exit 1). A value in the go env file cannot be
# overridden without dropping the user's other settings, so GOFLAGS/GOEXPERIMENT there fail closed (exit 2);
# GOAMD64/GOARM64 in the file are pinned by the script (exit 1).
knob() { # knob <name> <relfile> <constraint> <envassign> <fileassign> <want-rc> <want-regex>
  local name="$1" rel="$2" cons="$3" ev="$4" fv="$5" wrc="$6" wre="$7" d rc=0 out
  d="$T/case-knob-$name"
  cp -R "$base" "$d"
  put "$d" "$rel" "//go:build $cons" '' 'package p'
  if [ -n "$ev" ]; then
    out="$(env "$ev" "$BASH" "$here/check-js-scope.sh" -C "$d" "$scope" 2>&1)" || rc=$?
  else
    printf '%s\n' "$fv" > "$T/goenv-$name"
    out="$(GOENV="$T/goenv-$name" "$BASH" "$here/check-js-scope.sh" -C "$d" "$scope" 2>&1)" || rc=$?
  fi
  [ "$rc" -eq "$wrc" ] || fail "knob-$name: want exit $wrc, got $rc:"$'\n'"$out"
  grep -qE "$wre" <<<"$out" || fail "knob-$name: output does not match '$wre':"$'\n'"$out"
}
flagged='internal/p/z.go: compiled for js/wasm but for neither lint host'
knob flags-env internal/p/z.go 'js || foo' GOFLAGS=-tags=foo '' 1 "$flagged"
knob flags-file internal/p/z.go 'js || foo' '' GOFLAGS=-tags=foo 2 'check-js-scope: GOFLAGS is set in the go env file'
knob exp-env internal/p/z.go 'js || goexperiment.jsonv2' GOEXPERIMENT=jsonv2 '' 1 "$flagged"
knob exp-file internal/p/z.go 'js || goexperiment.jsonv2' '' GOEXPERIMENT=jsonv2 2 'check-js-scope: GOEXPERIMENT is set in the go env file'
knob amd64-env internal/p/z.go 'js || amd64.v3' GOAMD64=v3 '' 1 "$flagged"
knob amd64-file internal/p/z.go 'js || amd64.v3' '' GOAMD64=v3 1 "$flagged"
knob arm64-env internal/p/z.go 'js || arm64.v9.0' GOARM64=v9.0 '' 1 "$flagged"
knob arm64-file internal/p/z.go 'js || arm64.v9.0' '' GOARM64=v9.0 1 "$flagged"

# Errors fail closed (exit 2).
rc=0
out="$(run -C "$base" 2>&1)" || rc=$?
[ "$rc" -eq 2 ] || fail "no-pattern: want exit 2, got $rc:"$'\n'"$out"
rc=0
out="$(run -C "$base" ./nope/... 2>&1)" || rc=$?
[ "$rc" -eq 2 ] || fail "missing-dir: want exit 2, got $rc:"$'\n'"$out"
rc=0
out="$(run -C "$T/nomod" "$scope" 2>&1)" || rc=$?
[ "$rc" -eq 2 ] || fail "no-module: want exit 2, got $rc:"$'\n'"$out"

echo 'check-js-scope selftest: OK'
