#!/usr/bin/env bash
# Fail if a GitHub Actions uses: is not pinned to a full commit SHA.
# Every Action must be pinned by full commit SHA (ADR-0002 §1, sha_pinning_required);
# GitHub only enforces that at job setup, after the push. This gate catches it before.
# Usage: scripts/check-actions-pinned.sh [repo-dir]   (default: this repo)
# Plain bash 3.2-compatible: regexes live in variables, no mapfile, no associative arrays.
set -euo pipefail
dir="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
if [[ "${CHECK_ACTIONS_PINNED_DEBUG:-}" == 1 ]]; then
  echo "check-actions-pinned: debug: bash ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}" >&2
fi
# Always scan the whole repo, even when given a subdirectory.
root="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)" || {
  echo "check-actions-pinned: $dir is not inside a git work tree" >&2
  exit 1
}
cd "$root"
re_key='^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*(.*)$'
re_sha='^[^@[:space:]]+@[0-9a-f]{40}$'
bad=0
uses=0
files=0
while IFS= read -r f; do
  files=$((files + 1))
  n=0
  while IFS= read -r line || [[ -n $line ]]; do
    n=$((n + 1))
    [[ $line =~ $re_key ]] || continue
    uses=$((uses + 1))
    v="${BASH_REMATCH[2]}"
    v="${v%%[[:space:]]*}"
    if [[ ! $v =~ $re_sha ]]; then
      printf 'check-actions-pinned: %s:%s: uses: %s: not pinned to a full 40-hex lowercase commit SHA\n' "$f" "$n" "$v" >&2
      bad=1
    fi
  done < "$f"
done < <(git ls-files --cached --others --exclude-standard -- '.github/workflows/*.yml')
if (( bad )); then
  echo "check-actions-pinned: hint: pin by full commit SHA and keep the tag as a trailing comment, e.g. uses: owner/repo@<40 hex>  # vX.Y.Z (ADR-0002 §1)" >&2
  exit 1
fi
echo "check-actions-pinned: OK ($uses uses: in $files files)"
