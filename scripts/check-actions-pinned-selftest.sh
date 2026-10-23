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

# --- YAML forms: every bad line is reported in one run, no good line is. ---
forms="$T/.github/workflows/forms.yml"
fl=0
badl=""   # newline-separated "line|reason" pairs
goodl=""  # line numbers that must not be reported
put() { printf '%s\n' "$1" >> "$forms"; fl=$((fl + 1)); }
putraw() { printf '%s' "$1" >> "$forms"; fl=$((fl + 1)); }
bad()  { put "$1"; badl="$badl$fl|$2"$'\n'; }
good() { put "$1"; goodl="$goodl$fl "; }
up=0123456789ABCDEF0123456789ABCDEF01234567
long=0123456789abcdef0123456789abcdef012345678
dig=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
put 'jobs:'
bad  '      - uses: "actions/checkout@v4"  # q'                       'not pinned to a full 40-hex'
bad  "      - uses: 'actions/checkout@$up'"                           'not pinned to a full 40-hex'
bad  '    uses: org/repo/.github/workflows/f.yml@main'                'not pinned to a full 40-hex'
bad  '      - uses: actions/checkout'                                 'not pinned to a full 40-hex'
bad  '      - uses: actions/checkout@de0fac2'                         'not pinned to a full 40-hex'
bad  "      - uses: actions/checkout@$long"                           'not pinned to a full 40-hex'
bad  '      - uses:'                                                  '(empty)'
bad  '      - uses: "actions/checkout@v4'                             'unterminated quote'
bad  "      - uses: \"actions/checkout@$sha"                          'unterminated quote'
good "      - uses: \"owner/repo@$sha\""
good "      -   uses: owner/repo@$sha"
good "    uses: org/repo/.github/workflows/f.yml@$sha"
good '      # - uses: actions/checkout@v4'
good '      - uses: ./local-action'
good '    uses: ./.github/workflows/reuse.yml'
good "      - uses: docker://alpine@sha256:$dig"
bad  '      - uses: docker://alpine:3.20'                              'not pinned by @sha256:'
printf '      - uses: owner/repo@%s  # v1\r\n' "$sha" >> "$forms"; fl=$((fl + 1)); goodl="$goodl$fl "
git -C "$T" add -A
out="$(scan "$T" 2>&1)" && fail "expected failure on forms tree"
while IFS='|' read -r ln why; do
  [[ -n $ln ]] || continue
  grep -F "check-actions-pinned: .github/workflows/forms.yml:$ln:" <<<"$out" | grep -qF "$why" \
    || fail "forms.yml:$ln not reported with '$why'"
done <<<"$badl"
for ln in $goodl; do
  if grep -qF "forms.yml:$ln:" <<<"$out"; then fail "good line forms.yml:$ln flagged"; fi
done
git -C "$T" rm -q -f --cached .github/workflows/forms.yml && rm "$forms"

sed 's|actions/checkout@v4|actions/checkout@'"$sha"'  # v1|' "$wf" > "$wf.tmp" && mv "$wf.tmp" "$wf"
out="$(scan "$T" 2>&1)" || fail "fixed tree should pass: $out"
grep -qF "check-actions-pinned: OK (" <<<"$out" || fail "no OK line"
echo "check-actions-pinned selftest: OK (bash $ver)"
