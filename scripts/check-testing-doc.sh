#!/usr/bin/env bash
# Fail if any Go package under internal/ or pkg/ is missing from
# docs/engineering/testing.md.
#
# The testing doc is a contract: every package with code MUST have a row
# describing its test discipline. Skeleton directories (no .go files yet) are
# allowed to be unlisted — they get a row when the first behaviour lands.
#
# Run as part of `make check`.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
doc="$repo_root/docs/engineering/testing.md"

if [[ ! -f "$doc" ]]; then
  echo "check-testing-doc: missing $doc" >&2
  exit 2
fi

missing=()

# Find every directory under internal/ or pkg/ that contains at least one
# non-test .go file. -name '*.go' ! -name '*_test.go' is the package gate.
while IFS= read -r dir; do
  rel="${dir#"$repo_root/"}"
  # Match the package path in a backticked code span, e.g. `internal/policy`.
  if ! grep -qF "\`${rel}\`" "$doc"; then
    missing+=("$rel")
  fi
done < <(
  find "$repo_root/internal" "$repo_root/pkg" \
       -type f -name '*.go' ! -name '*_test.go' 2>/dev/null \
    | xargs -n1 dirname \
    | sort -u
)

if (( ${#missing[@]} > 0 )); then
  echo "check-testing-doc: the following Go packages have code but no row in docs/engineering/testing.md:" >&2
  for pkg in "${missing[@]}"; do
    echo "  - $pkg" >&2
  done
  echo "" >&2
  echo "Add a row to the per-surface table in docs/engineering/testing.md (or move an existing skeleton row up by dropping its *(skeleton)* marker) in the same commit that introduces the package." >&2
  exit 1
fi
