#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fail if a Go file compiled for js/wasm but for neither lint host (linux/amd64, darwin/arm64) sits outside the js/wasm lint scope.
# Usage: check-js-scope.sh [-C module-dir] pattern...   (patterns: the js/wasm lint scope, WASM_PKG in the Makefile)
# Exit: 0 clean, 1 violation(s), 2 usage or toolchain error.
set -euo pipefail
export GOWORK=off GOFLAGS= CGO_ENABLED=0 LC_ALL=C
unset GOEXPERIMENT GOAMD64 GOARM64
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

cd "$dir"
gomod="$("$GO" env GOMOD)"
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
tmpl='{{$d:=.Dir}}{{range .GoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}{{range .TestGoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}{{range .XTestGoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}'

list() { # list <out> <goos> <goarch> <args...>
  local out="$1" os="$2" arch="$3"
  shift 3
  if ! GOOS="$os" GOARCH="$arch" "$GO" list "$@" > "$out.raw"; then
    echo "check-js-scope: go list failed (GOOS=$os GOARCH=$arch)" >&2
    exit 2
  fi
  sort -u "$out.raw" > "$out"
}

list "$T/js" js wasm -e -f "$tmpl" ./...
list "$T/h1" linux amd64 -e -f "$tmpl" ./...
list "$T/h2" darwin arm64 -e -f "$tmpl" ./...
list "$T/scope" js wasm -f '{{.Dir}}' "$@"
sort -u "$T/h1" "$T/h2" > "$T/host"
comm -23 "$T/js" "$T/host" > "$T/jsonly"

scopetxt="$*"
n=0
: > "$T/viol"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  d="${f%/*}"
  if grep -qxF "$d" "$T/scope"; then
    n=$((n + 1))
    continue
  fi
  rel="${f#"$root"/}"
  pkg="${d#"$root"}"
  pkg="${pkg#/}"
  [ -n "$pkg" ] || pkg="."
  echo "check-js-scope: $rel: compiled for js/wasm but for neither lint host (linux/amd64, darwin/arm64); package $pkg is outside the js/wasm lint scope ($scopetxt)" >> "$T/viol"
done < "$T/jsonly"

if [ -s "$T/viol" ]; then
  sort "$T/viol" >&2
  echo "check-js-scope: hint: move the file into the js/wasm lint scope, or add its package to WASM_PKG in the Makefile so make lint and make wasm-check cover it" >&2
  exit 1
fi
echo "check-js-scope: OK ($n js-only Go file(s), all in scope)"
