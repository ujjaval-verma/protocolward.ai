#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Self-test for check-js-scope.sh: a green baseline, 21 one-file violation cases (js form and darwin form), a js-or-darwin file covered by the js/wasm lint scope, the known cgo-off darwin residual (passes),
# a host package importing a package excluded under js/wasm, a two-violation case, the scope argument, -C to a subdirectory, 12 toolchain-knob cases and the exit-2 cases.
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
# run <args...>: run the check, capturing stdout in $so, stderr in $se and the exit status in $rc.
run() {
  rc=0
  "$BASH" "$here/check-js-scope.sh" "$@" > "$T/stdout" 2> "$T/stderr" || rc=$?
  so="$(cat "$T/stdout")"
  se="$(cat "$T/stderr")"
}
# expect_ok <name> <want-line> <args...>: exit 0, exactly <want-line> on stdout, nothing on stderr.
expect_ok() {
  local name="$1" want="$2"
  shift 2
  run "$@"
  if [ "$rc" -ne 0 ] || [ "$so" != "$want" ] || [ -n "$se" ]; then
    fail "$name: want exit 0, stdout exactly '$want', empty stderr; got rc=$rc stdout='$so' stderr='$se'"
  fi
}
# expect_2 <name> <want-stderr-substring> <args...>: exit 2, empty stdout, message on stderr.
expect_2() {
  local name="$1" want="$2"
  shift 2
  run "$@"
  [ "$rc" -eq 2 ] || fail "$name: want exit 2, got $rc: stdout='$so' stderr='$se'"
  [ -z "$so" ] || fail "$name: want empty stdout, got '$so'"
  grep -qF "$want" <<<"$se" || fail "$name: stderr lacks '$want':"$'\n'"$se"
}

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
put "$base" internal/p/q.go '//go:build darwin || linux' '' 'package p'
put "$base" internal/p/q_amd64.go 'package p'
put "$base" internal/p/u.go '//go:build ignore' '' 'package p'
put "$base" internal/p/v.go '//go:build wasip1' '' 'package p'
put "$base" internal/p/p_linux.go 'package p'
put "$base" internal/p/testdata/w_js.go 'package w'
put "$base" _skip/y_js.go 'package y'
mkdir "$T/nomod"
# The no-module case needs a directory outside every Go module; TMPDIR inside one would silently find that module.
nomodgomod="$(cd "$T/nomod" && GOWORK=off "$GO" env GOMOD)"
if [ -n "$nomodgomod" ] && [ "$nomodgomod" != /dev/null ]; then
  fail "precondition: TMPDIR ($T) is inside the Go module $nomodgomod; point TMPDIR outside any Go module"
fi

hint='check-js-scope: hint: CI lints linux/amd64, plus js/wasm for WASM_PKG in the Makefile; make the file build for linux/amd64 too, or, for js/wasm code, move it into WASM_PKG or add its package there so make lint and make wasm-check cover it; a file that must stay darwin-only first needs a darwin lint pass in CI, as a separate change'
scope='./cmd/wardwasm/...'
ok2='check-js-scope: OK (2 Go file(s) not built for linux/amd64, all in the js/wasm lint scope)'

# Baseline: without a green unmodified fixture, a red case proves nothing.
expect_ok baseline "$ok2" -C "$base" "$scope"

# Base files that no violation case may name (full module-relative paths).
base_files="$(cd "$base" && find . -type f | sed 's|^\./||' | sort)"

# violation <name> <relfile> <plats> <pkgdir-as-printed> <content...>
# <plats> is what the js form prints after "compiled for"; "-" selects the darwin form (and <pkgdir> is then "-").
violation() {
  local name="$1" rel="$2" plats="$3" pkg="$4"
  shift 4
  local d="$T/case-$name" out want f
  cp -R "$base" "$d"
  put "$d" "$rel" "$@"
  run -C "$d" "$scope"
  out="$se"
  [ "$rc" -eq 1 ] || fail "$name: want exit 1, got $rc:"$'\n'"stdout: $so"$'\n'"stderr: $se"
  [ -z "$so" ] || fail "$name: want empty stdout, got '$so'"
  if [ "$plats" = - ]; then
    want="check-js-scope: $rel: compiled for darwin/arm64 but not for linux/amd64 with cgo off, the CI lint reference, nor for js/wasm; no CI lint pass is known to see it"
  else
    want="check-js-scope: $rel: compiled for $plats but not for linux/amd64 with cgo off, the CI lint reference; package $pkg is outside the js/wasm lint scope ($scope)"
  fi
  [ "$(grep -cF ': compiled for ' <<<"$out")" -eq 1 ] || fail "$name: want exactly one violation line:"$'\n'"$out"
  grep -qxF "$want" <<<"$out" || fail "$name: missing line '$want':"$'\n'"$out"
  grep -qxF "$hint" <<<"$out" || fail "$name: missing hint line:"$'\n'"$out"
  if grep -q 'OK' <<<"$out"; then fail "$name: printed OK:"$'\n'"$out"; fi
  while IFS= read -r f; do
    if grep -qF "$f" <<<"$out"; then fail "$name: names base file $f:"$'\n'"$out"; fi
  done <<<"$base_files"
}

both='js/wasm and darwin/arm64'
violation js-or-darwin internal/p/s.go "$both" internal/p '//go:build js || darwin' '' 'package p'
violation not-linux internal/p/n.go "$both" internal/p '//go:build !linux' '' 'package p'
violation build-darwin internal/p/m.go - - '//go:build darwin' '' 'package p'
violation suffix-darwin internal/p/m_darwin.go - - 'package p'
violation darwin-test internal/p/m_darwin_test.go - - 'package p'
violation suffix-arm64 internal/p/r_arm64.go - - 'package p'
violation darwin-in-scope cmd/wardwasm/m_darwin.go - - 'package main'
violation cgo-darwin internal/p/k_darwin.go - - 'package p' '' 'import "C"'
violation build-darwin-cgo internal/p/c.go - - '//go:build darwin && cgo' '' 'package p'
violation js-or-cgo internal/p/j.go "$both" internal/p '//go:build js || cgo' '' 'package p'
violation build-js internal/p/a.go js/wasm internal/p '//go:build js' '' 'package p'
violation suffix-js internal/p/b_js.go js/wasm internal/p 'package p'
violation suffix-wasm internal/p/c_wasm.go js/wasm internal/p 'package p'
violation build-wasm internal/p/d.go js/wasm internal/p '//go:build wasm' '' 'package p'
violation exclusions internal/p/e.go js/wasm internal/p '//go:build !linux && !darwin' '' 'package p'
violation plus-build internal/p/l.go js/wasm internal/p '// +build js' '' 'package p'
violation test-file internal/p/f_js_test.go js/wasm internal/p 'package p'
violation xtest internal/p/g_test.go js/wasm internal/p '//go:build js' '' 'package p_test'
violation neighbour cmd/wardwasmx/h.go js/wasm cmd/wardwasmx '//go:build js' '' 'package h'
violation whole-package internal/onlyjs/o_js.go js/wasm internal/onlyjs 'package onlyjs'
violation root-package k_js.go js/wasm . 'package k'

# A js || darwin file in a WASM_PKG package is compiled by the js/wasm lint pass, so it is covered.
d="$T/case-js-or-darwin-in-scope"
cp -R "$base" "$d"
put "$d" cmd/wardwasm/s.go '//go:build js || darwin' '' 'package main'
expect_ok js-or-darwin-in-scope 'check-js-scope: OK (3 Go file(s) not built for linux/amd64, all in the js/wasm lint scope)' -C "$d" "$scope"

# Known residual, recorded in ADR-0002 (issue #123): darwin/arm64 is listed with cgo on, so a cgo-off darwin file is not checked.
# This case is expected to flip to a violation when a darwin lint pass is added.
d="$T/case-residual-darwin-nocgo"
cp -R "$base" "$d"
put "$d" internal/p/z.go '//go:build darwin && !cgo' '' 'package p'
expect_ok residual-darwin-nocgo "$ok2" -C "$d" "$scope"

# Two violations of different forms in one run: both reported, sorted, one hint, nothing on stdout.
d="$T/case-multi"
cp -R "$base" "$d"
put "$d" internal/p/a.go '//go:build js' '' 'package p'
put "$d" internal/p/m_darwin.go 'package p'
run -C "$d" "$scope"
[ "$rc" -eq 1 ] || fail "multi: want exit 1, got $rc:"$'\n'"stdout: $so"$'\n'"stderr: $se"
[ -z "$so" ] || fail "multi: want empty stdout, got '$so'"
want1="check-js-scope: internal/p/a.go: compiled for js/wasm but not for linux/amd64 with cgo off, the CI lint reference; package internal/p is outside the js/wasm lint scope ($scope)"
want2='check-js-scope: internal/p/m_darwin.go: compiled for darwin/arm64 but not for linux/amd64 with cgo off, the CI lint reference, nor for js/wasm; no CI lint pass is known to see it'
[ "$se" = "$want1"$'\n'"$want2"$'\n'"$hint" ] || fail "multi: want the two violation lines in order, then the hint; got:"$'\n'"$se"

# Scope comes from the arguments.
expect_ok scope-arg 'check-js-scope: OK (3 Go file(s) not built for linux/amd64, all in the js/wasm lint scope)' -C "$T/case-whole-package" "$scope" ./internal/onlyjs

# A host package importing a package excluded under js/wasm must not make the gate fail (go list -e).
d="$T/case-host-only-import"
cp -R "$base" "$d"
put "$d" internal/hostonly/h.go '//go:build linux || darwin' '' 'package hostonly'
put "$d" internal/p/imp.go 'package p' '' 'import _ "example.test/m/internal/hostonly"'
expect_ok host-only-import "$ok2" -C "$d" "$scope"

# -C may name a subdirectory; patterns still resolve from the module root.
expect_ok subdir "$ok2" -C "$base/internal" "$scope"

# Toolchain knobs: the verdict must not depend on the caller's GOFLAGS/GOEXPERIMENT/GOAMD64/GOARM64/CGO_ENABLED.
# Each decoy is compiled for js/wasm or darwin/arm64 but not for linux/amd64 only while the knob is at the value the
# script pins, so it must be flagged; a knob that leaked into the lists would let the gate pass it.
# An exported variable is overridden by the script (exit 1). GOFLAGS/GOEXPERIMENT in the go env file cannot be
# overridden without dropping the user's other settings, so they fail closed (exit 2);
# GOAMD64/GOARM64/CGO_ENABLED in the file are beaten by the script's explicit values (exit 1).
knob() { # knob <name> <relfile> <constraint> <envassign> <fileassign> <want-rc> <want-regex>
  local name="$1" rel="$2" cons="$3" ev="$4" fv="$5" wrc="$6" wre="$7" d out rc=0
  d="$T/case-knob-$name"
  cp -R "$base" "$d"
  put "$d" "$rel" "//go:build $cons" '' 'package p'
  if [ -n "$ev" ]; then
    env "$ev" "$BASH" "$here/check-js-scope.sh" -C "$d" "$scope" > "$T/stdout" 2> "$T/stderr" || rc=$?
  else
    printf '%s\n' "$fv" > "$T/goenv-$name"
    GOENV="$T/goenv-$name" "$BASH" "$here/check-js-scope.sh" -C "$d" "$scope" > "$T/stdout" 2> "$T/stderr" || rc=$?
  fi
  out="$(cat "$T/stdout" "$T/stderr")"
  [ "$rc" -eq "$wrc" ] || fail "knob-$name: want exit $wrc, got $rc:"$'\n'"$out"
  grep -qE "$wre" <<<"$out" || fail "knob-$name: output does not match '$wre':"$'\n'"$out"
}
flagged='internal/p/z.go: compiled for js/wasm but not for linux/amd64'
flaggedmac='internal/p/z.go: compiled for darwin/arm64 but not for linux/amd64'
knob flags-env internal/p/z.go 'js || foo' GOFLAGS=-tags=foo '' 1 "$flagged"
knob flags-file internal/p/z.go 'js || foo' '' GOFLAGS=-tags=foo 2 'check-js-scope: GOFLAGS is set in the go env file'
knob exp-env internal/p/z.go 'js || goexperiment.jsonv2' GOEXPERIMENT=jsonv2 '' 1 "$flagged"
knob exp-file internal/p/z.go 'js || goexperiment.jsonv2' '' GOEXPERIMENT=jsonv2 2 'check-js-scope: GOEXPERIMENT is set in the go env file'
knob amd64-env internal/p/z.go 'js || amd64.v3' GOAMD64=v3 '' 1 "$flagged"
knob amd64-file internal/p/z.go 'js || amd64.v3' '' GOAMD64=v3 1 "$flagged"
knob arm64-env internal/p/z.go 'darwin && arm64 && !arm64.v9.0' GOARM64=v9.0 '' 1 "$flaggedmac"
knob arm64-file internal/p/z.go 'darwin && arm64 && !arm64.v9.0' '' GOARM64=v9.0 1 "$flaggedmac"
knob cgo-mac-env internal/p/z.go 'darwin && cgo' CGO_ENABLED=0 '' 1 "$flaggedmac"
knob cgo-ref-env internal/p/z.go 'cgo' CGO_ENABLED=1 '' 1 "$flaggedmac"
knob cgo-mac-file internal/p/z.go 'darwin && cgo' '' CGO_ENABLED=0 1 "$flaggedmac"
knob cgo-ref-file internal/p/z.go 'cgo' '' CGO_ENABLED=1 1 "$flaggedmac"

# Errors fail closed (exit 2), with the reason on stderr and nothing on stdout.
expect_2 no-pattern 'usage: check-js-scope.sh' -C "$base"
expect_2 no-dir-arg 'usage: check-js-scope.sh' -C
expect_2 missing-dir 'go list failed (GOOS=js GOARCH=wasm CGO_ENABLED=0)' -C "$base" ./nope/...
expect_2 no-module 'no Go module found' -C "$T/nomod" "$scope"
expect_2 missing-C-dir 'cannot cd to' -C "$T/does-not-exist" "$scope"
GO=/nonexistent/go expect_2 missing-go '/nonexistent/go env' -C "$base" "$scope"
cat > "$T/failgo" <<GOEOF
#!/bin/sh
[ "\$2" = GOMOD ] && exit 3
exec "$GO" "\$@"
GOEOF
chmod +x "$T/failgo"
GO="$T/failgo" expect_2 failing-gomod 'env GOMOD failed' -C "$base" "$scope"

echo 'check-js-scope selftest: OK'
