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
# NUL-separated list in a temp file (bash cannot hold NUL in a variable) so a git failure is seen, not swallowed by <( ).
list="$(mktemp)"
trap 'rm -f "$list"' EXIT
git ls-files -z --cached --others --exclude-standard -- '.github/workflows/*.yml' '.github/workflows/*.yaml' \
  '.github/actions/action.yml' '.github/actions/action.yaml' \
  '.github/actions/**/action.yml' '.github/actions/**/action.yaml' > "$list" || {
  echo "check-actions-pinned: git ls-files failed" >&2
  exit 1
}
re_key='^([[:space:]]*)(-[[:space:]]+)?([!&][^[:space:]]*[[:space:]]+)*uses[[:space:]]*:[[:space:]]*(.*)$'
re_ind='^([[:space:]]*)(.*)$'
re_tail='^([[:space:]]+#.*|[[:space:]]*)$'   # after a closing quote: only whitespace or a # comment
re_dq='^"([^"]*)"'
re_sq="^'([^']*)'"
re_docker='^docker://[^@[:space:]]+@sha256:[0-9a-f]{64}$'
re_sha='^[^@[:space:]]+@[0-9a-f]{40}$'
bad=0
uses=0
files=0
while IFS= read -r -d '' f; do
  if [[ ! -f $f ]]; then
    # --cached lists a tracked file deleted from the work tree but not staged; this gate checks the work tree (ADR-0002 §2).
    echo "check-actions-pinned: note: $f: tracked but missing from the work tree; skipped: this gate checks the work tree; the pushed commits may still contain it (ADR-0002 §2)" >&2
    continue
  fi
  files=$((files + 1))
  n=0
  pend=""
  pend_col=0
  while IFS= read -r line || [[ -n $line ]]; do
    n=$((n + 1))
    if [[ -n $pend ]]; then
      # A more-indented line right after uses: continues the scalar (blank lines are skipped, a comment ends it).
      [[ $line =~ $re_ind ]]
      ind="${#BASH_REMATCH[1]}"
      rest="${BASH_REMATCH[2]%$'\r'}"
      if [[ -n $rest ]]; then
        if [[ $rest != '#'* ]] && (( ind > pend_col )); then
          printf 'check-actions-pinned: %s:%s: uses: value continues on the next line\n' "$f" "$pend" >&2
          bad=1
        fi
        pend=""
      fi
    fi
    [[ $line =~ $re_key ]] || continue
    uses=$((uses + 1))
    pend="$n"
    pend_col=$(( ${#BASH_REMATCH[1]} + ${#BASH_REMATCH[2]} ))
    v="${BASH_REMATCH[4]}"
    v="${v%$'\r'}"
    reason="not pinned to a full 40-hex lowercase commit SHA"
    ok=0
    if [[ $v =~ $re_dq || $v =~ $re_sq ]]; then
      q="${BASH_REMATCH[1]}"
      tail="${v:${#BASH_REMATCH[0]}}"
      if [[ ! $tail =~ $re_tail ]]; then
        printf 'check-actions-pinned: %s:%s: uses: %s: unexpected text after the closing quote\n' "$f" "$n" "$v" >&2
        bad=1
        continue
      fi
      v="$q"
    elif [[ $v == \"* || $v == \'* ]]; then
      printf 'check-actions-pinned: %s:%s: uses: %s: unterminated quote\n' "$f" "$n" "$v" >&2
      bad=1
      continue
    else
      v="${v%%[[:space:]]*}"
    fi
    if [[ -z $v ]]; then
      reason="(empty)"
    elif [[ $v == ./* ]]; then
      ok=1   # local action or reusable workflow: in this repo at the checked-out commit
    elif [[ $v == docker://* ]]; then
      reason="not pinned by @sha256:<64 hex> digest"
      [[ $v =~ $re_docker ]] && ok=1
    elif [[ $v =~ $re_sha ]]; then
      ok=1
    fi
    if (( ! ok )); then
      printf 'check-actions-pinned: %s:%s: uses: %s: %s\n' "$f" "$n" "$v" "$reason" >&2
      bad=1
    fi
  done < "$f"
done < "$list"
if (( bad )); then
  echo "check-actions-pinned: hint: pin by full commit SHA and keep the tag as a trailing comment, e.g. uses: owner/repo@<40 hex>  # vX.Y.Z (ADR-0002 §1)" >&2
  exit 1
fi
echo "check-actions-pinned: OK ($uses uses: in $files files)"
