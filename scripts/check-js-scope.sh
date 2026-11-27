#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fail if a Go file compiled for js/wasm or darwin/arm64 (cgo on, as a Mac lints it) but not for linux/amd64 (cgo off; the CI lint host) is outside what CI lints (js/wasm files in the js/wasm lint scope).
# Usage: check-js-scope.sh [-C module-dir] pattern...   (patterns: the js/wasm lint scope, WASM_PKG in the Makefile)
# Exit: 0 clean, 1 violation(s), 2 usage or toolchain error.
set -euo pipefail
# cmd/go falls back to the go env file (go env -w) when a variable is empty or unset, so clearing GOFLAGS and
# GOEXPERIMENT only beats the caller's environment. GOAMD64/GOARM64 are pinned to their defaults (non-empty,
# so they beat the file too); a GOFLAGS/GOEXPERIMENT in the file is rejected below. Each list below also passes
# CGO_ENABLED explicitly: the darwin/arm64 list overrides it to 1, as a Mac's lint sees cgo files.
export GOWORK=off GOFLAGS= CGO_ENABLED=0 LC_ALL=C GOAMD64=v1 GOARM64=v8.0
unset GOEXPERIMENT
GO="${GO:-go}"

dir="$(cd "$(dirname "$0")/.." && pwd)"
if [ "${1:-}" = "-C" ]; then
  [ $# -ge 2 ] || { echo "usage: check-js-scope.sh [-C module-dir] pattern..." >&2; exit 2; }
  dir="$2"
  shift 2
fi
if [ $# -lt 1 ]; then
  echo "usage: check-js-scope.sh [-C module-dir] pattern..." >&2
  exit 2
fi

for knob in GOFLAGS GOEXPERIMENT; do
  val="$("$GO" env "$knob")" || { echo "check-js-scope: $GO env $knob failed" >&2; exit 2; }
  if [ -n "$val" ]; then
    echo "check-js-scope: $knob is set in the go env file ($("$GO" env GOENV)) and would change which files are compiled; unset it with: go env -u $knob" >&2
    exit 2
  fi
done

cd "$dir" 2>/dev/null || { echo "check-js-scope: cannot cd to $dir" >&2; exit 2; }
gomod="$("$GO" env GOMOD)" || { echo "check-js-scope: $GO env GOMOD failed" >&2; exit 2; }
if [ -z "$gomod" ] || [ "$gomod" = "/dev/null" ]; then
  echo "check-js-scope: no Go module found in $dir" >&2
  exit 2
fi
root="$(dirname "$gomod")"
cd "$root"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# The three universe lists use -e so a host-only import does not break loading under js/wasm;
# the scope list is strict so a missing directory still exits 2.
tmpl='{{$d:=.Dir}}{{range .GoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}{{range .CgoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}{{range .TestGoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}{{range .XTestGoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}'

list() { # list <out> <goos> <goarch> <cgo> <args...>
  local out="$1" os="$2" arch="$3" cgo="$4"
  shift 4
  if ! CGO_ENABLED="$cgo" GOOS="$os" GOARCH="$arch" "$GO" list "$@" > "$out.raw"; then
    echo "check-js-scope: go list failed (GOOS=$os GOARCH=$arch)" >&2
    exit 2
  fi
  sort -u "$out.raw" > "$out"
}

# JS: js/wasm; MAC: darwin/arm64 with cgo on, as a Mac's lint sees it; REF: linux/amd64 with cgo off, the CI lint host.
list "$T/js" js wasm 0 -e -f "$tmpl" ./...
list "$T/mac" darwin arm64 1 -e -f "$tmpl" ./...
list "$T/ref" linux amd64 0 -e -f "$tmpl" ./...
list "$T/scope" js wasm 0 -f '{{.Dir}}' "$@"
sort -u "$T/js" "$T/mac" > "$T/cand"
comm -23 "$T/cand" "$T/ref" > "$T/notref"

scopetxt="$*"
n=0
: > "$T/viol"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  d="${f%/*}"
  injs=0
  grep -qxF "$f" "$T/js" && injs=1
  if [ "$injs" -eq 1 ] && grep -qxF "$d" "$T/scope"; then
    n=$((n + 1))
    continue
  fi
  rel="${f#"$root"/}"
  if [ "$injs" -eq 1 ]; then
    plats="js/wasm"
    if grep -qxF "$f" "$T/mac"; then plats="js/wasm and darwin/arm64"; fi
    pkg="${d#"$root"}"
    pkg="${pkg#/}"
    [ -n "$pkg" ] || pkg="."
    echo "check-js-scope: $rel: compiled for $plats but not for linux/amd64 with cgo off, the CI lint reference; package $pkg is outside the js/wasm lint scope ($scopetxt)" >> "$T/viol"
  else
    echo "check-js-scope: $rel: compiled for darwin/arm64 but not for linux/amd64 with cgo off, the CI lint reference, nor for js/wasm; no CI lint pass is known to see it" >> "$T/viol"
  fi
done < "$T/notref"

if [ -s "$T/viol" ]; then
  sort "$T/viol" >&2
  echo "check-js-scope: hint: CI lints linux/amd64, plus js/wasm for WASM_PKG in the Makefile; make the file build for linux/amd64 too, or, for js/wasm code, move it into WASM_PKG or add its package there so make lint and make wasm-check cover it; a file that must stay darwin-only first needs a darwin lint pass in CI, as a separate change" >&2
  exit 1
fi
echo "check-js-scope: OK ($n Go file(s) not built for linux/amd64, all in the js/wasm lint scope)"
