#!/usr/bin/env bash
# Self-test for check-spdx.sh: a missing or wrong header must fail, a correct one must pass.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
git -C "$T" init -q
mkdir -p "$T/pkg/a" "$T/internal/b" "$T/cmd/c"
printf '// SPDX-License-Identifier: Apache-2.0\n\npackage a\n'    > "$T/pkg/a/a.go"
printf '// SPDX-License-Identifier: AGPL-3.0-only\n\npackage b\n' > "$T/internal/b/b.go"
printf 'package c\n'                                             > "$T/cmd/c/c.go"
git -C "$T" add -A
out="$("$here/check-spdx.sh" "$T" 2>&1)" && { echo "check-spdx selftest: expected failure on bad tree" >&2; exit 1; }
for want in cmd/c/c.go internal/b/b.go; do
  grep -q "$want" <<<"$out" || { echo "check-spdx selftest: $want not reported" >&2; exit 1; }
done
if grep -q "pkg/a/a.go" <<<"$out"; then echo "check-spdx selftest: good file flagged" >&2; exit 1; fi
# A subdirectory argument still scans the whole repo.
"$here/check-spdx.sh" "$T/pkg/a" >/dev/null 2>&1 && { echo "check-spdx selftest: subdir run missed repo root" >&2; exit 1; }
for f in internal/b/b.go cmd/c/c.go; do
  { printf '// SPDX-License-Identifier: Apache-2.0\n\n'; grep -v '^// SPDX' "$T/$f" | sed '/./,$!d'; } > "$T/$f.tmp" && mv "$T/$f.tmp" "$T/$f"
done
"$here/check-spdx.sh" "$T" >/dev/null || { echo "check-spdx selftest: fixed tree should pass" >&2; exit 1; }
echo "check-spdx selftest: OK"
