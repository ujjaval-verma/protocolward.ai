#!/usr/bin/env bash
# Self-test for check-actions-pinned.sh: an unpinned uses: must fail with its path:line, a pinned one must pass.
# The scanner always runs under "$BASH" (the interpreter running this file), never via its shebang,
# so a bash 3.2 run really exercises the scanner under bash 3.2.
set -euo pipefail
# Builds throwaway repos with `git -C`; drop any inherited GIT_DIR/GIT_INDEX_FILE/...
# (git exports GIT_DIR to hooks and `rebase -x` in a linked worktree) so they cannot touch the caller's repo.
unset $(git rev-parse --local-env-vars)
here="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
N="$(mktemp -d)"
trap 'rm -rf "$T" "${N:-}"' EXIT
git -C "$T" init -q
ver="${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"
scan() { "$BASH" "$here/check-actions-pinned.sh" "$@"; }
fail() { echo "check-actions-pinned selftest: $*" >&2; exit 1; }
sha=0123456789abcdef0123456789abcdef01234567

mkdir -p "$T/.github/workflows"
wf="$T/.github/workflows/a.yml"
{
  printf 'name: a\n'                                          # 1
  printf 'jobs:\n'                                            # 2
  printf '  j:\n'                                             # 3
  printf '    steps:\n'                                       # 4
  printf '      - uses: actions/checkout@v4\n'                # 5 bad
  printf '      - uses: actions/checkout@%s  # v1\n' "$sha"   # 6 good
} > "$wf"
git -C "$T" add -A
out="$(scan "$T" 2>&1)" && fail "expected failure on bad tree"
grep -qF "check-actions-pinned: .github/workflows/a.yml:5:" <<<"$out" || fail "a.yml:5 not reported"
if grep -qF "a.yml:6:" <<<"$out"; then fail "good line flagged"; fi
dbg="$(CHECK_ACTIONS_PINNED_DEBUG=1 scan "$T" 2>&1 || true)"
grep -qF "check-actions-pinned: debug: bash $ver" <<<"$dbg" || fail "scanner did not run under bash $ver"

sed 's|actions/checkout@v4|actions/checkout@'"$sha"'  # v1|' "$wf" > "$wf.tmp" && mv "$wf.tmp" "$wf"
out="$(scan "$T" 2>&1)" || fail "fixed tree should pass: $out"
grep -qF "check-actions-pinned: OK (" <<<"$out" || fail "no OK line"
echo "check-actions-pinned selftest: OK (bash $ver)"
