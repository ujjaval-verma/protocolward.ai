#!/usr/bin/env bash
# Fail if a Go file does not start with the project's SPDX licence line.
# The whole repository is Apache-2.0 (ADR-0007), so there is one identifier.
# Usage: scripts/check-spdx.sh [repo-dir]   (default: this repo)
set -euo pipefail
dir="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
# Always scan the whole repo, even when given a subdirectory.
root="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)" || {
  echo "check-spdx: $dir is not inside a git work tree" >&2
  exit 1
}
cd "$root"
want="// SPDX-License-Identifier: Apache-2.0"
bad=0
while IFS= read -r f; do
  first="$(head -n1 "$f")"
  if [[ "$first" != "$want" ]]; then
    printf 'check-spdx: %s: first line must be %q\n' "$f" "$want" >&2
    bad=1
  fi
done < <(git ls-files --cached --others --exclude-standard -- '*.go')
if (( bad )); then
  echo "check-spdx: hint: go generate (stringer) rewrites *_string.go without the header; re-add it after regenerating" >&2
  exit 1
fi
echo "check-spdx: OK"
