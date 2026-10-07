#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Collect the licence texts of every third-party Go module linked into a
# binary, plus the Go standard library's, so binary archives carry them.
#
# Usage: scripts/third-party-licenses.sh <out-dir> [module-dir] [main-pkg]
#   defaults: module-dir = this repo, main-pkg = ./cmd/ward
#
# Output (regenerated from scratch, deterministic order):
#   <out-dir>/MODULES.txt                      one "path version" line per module
#   <out-dir>/go-stdlib/{LICENSE,PATENTS}      Go standard library (statically linked)
#   <out-dir>/<module path>/<file>             LICENSE*, LICENCE*, COPYING*, NOTICE*, PATENTS*
#                                              copied verbatim from the module root
#
# Exits non-zero if any linked module has no licence file at its root.
# Run by the goreleaser `before` hook; checked by scripts/check-third-party-licenses.sh.
#
# <out-dir> is relative to the caller's cwd. It must be absent or a previous
# output of this script (it holds MODULES.txt); anything else is refused, so a
# typo cannot delete a real directory.
#
# The module set is the union over the released platforms in TARGETS.
# scripts/check-third-party-licenses.sh fails if TARGETS drifts from the
# goos/goarch matrix (minus ignore) in .goreleaser.yaml.
#
# Usage: scripts/third-party-licenses.sh --print-targets   prints TARGETS, one per line

set -euo pipefail

TARGETS="${TARGETS:-darwin/arm64 linux/amd64 linux/arm64}"

if [[ "${1:-}" == "--print-targets" ]]; then
  printf '%s\n' $TARGETS
  exit 0
fi

out="${1:?usage: third-party-licenses.sh <out-dir> [module-dir] [main-pkg]}"
moddir="${2:-$(cd "$(dirname "$0")/.." && pwd)}"
pkg="${3:-./cmd/ward}"

# Resolve against the caller's cwd before the cd below.
[[ "$out" == /* ]] || out="$PWD/$out"
if [[ -e "$out" && ! -f "$out/MODULES.txt" ]]; then
  echo "third-party-licenses: refusing out-dir '$out': it exists and is not a previous output (no MODULES.txt)" >&2
  exit 2
fi

cd "$moddir"
export LC_ALL=C CGO_ENABLED=0

# A fresh CI runner has an empty module cache; fetch what the build graph needs.
go mod download

main="$(go list -m)"
list="$(mktemp)"
trap 'rm -f "$list"' EXIT

for t in $TARGETS; do
  GOOS="${t%/*}" GOARCH="${t#*/}" go list -deps \
    -f '{{with .Module}}{{.Path}}|{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}|{{.Dir}}{{end}}' \
    "$pkg" >>"$list"
done

rm -rf "$out"
mkdir -p "$out"

# Go standard library: BSD-3-Clause, statically linked into every binary.
goroot="$(go env GOROOT)"
mkdir -p "$out/go-stdlib"
cp "$goroot/LICENSE" "$out/go-stdlib/LICENSE"
if [[ -f "$goroot/PATENTS" ]]; then cp "$goroot/PATENTS" "$out/go-stdlib/PATENTS"; fi
printf 'go-stdlib %s\n' "$(go env GOVERSION)" >"$out/MODULES.txt"

missing=0
# '|' not tab: a tab is IFS whitespace, so an empty version field would collapse.
while IFS='|' read -r path version dir; do
  [[ -z "$path" || "$path" == "$main" ]] && continue
  if [[ -z "$dir" || ! -d "$dir" ]]; then
    echo "third-party-licenses: $path: module directory not found ('$dir')" >&2
    missing=1
    continue
  fi
  found=0
  while IFS= read -r f; do
    mkdir -p "$out/$path"
    cp "$f" "$out/$path/"
    found=1
  done < <(find "$dir" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'LICENCE*' \
             -o -iname 'COPYING*' -o -iname 'NOTICE*' -o -iname 'PATENTS*' \) | sort)
  if (( found == 0 )); then
    echo "third-party-licenses: $path${version:+@$version}: no LICENSE/LICENCE/COPYING file at $dir — remediation: replace or drop the dependency" >&2
    missing=1
    continue
  fi
  if ! find "$out/$path" -maxdepth 1 -type f \( -iname 'LICEN[CS]E*' -o -iname 'COPYING*' \) | grep -q .; then
    echo "third-party-licenses: $path${version:+@$version}: only NOTICE/PATENTS found, no licence text at $dir" >&2
    missing=1
    continue
  fi
  printf '%s %s\n' "$path" "${version:-(devel)}" >>"$out/MODULES.txt"
done < <(sort -u "$list")

if (( missing )); then
  echo "third-party-licenses: one or more linked modules lack a licence file; not generating $out" >&2
  rm -rf "$out"
  exit 1
fi

# Files from the module cache are read-only; make the tree removable.
chmod -R u+w "$out"
