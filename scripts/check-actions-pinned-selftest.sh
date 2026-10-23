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
R="$(mktemp -d)"   # parent of the per-case throwaway repos
trap 'rm -rf "$T" "${N:-}" "${R:-}"' EXIT
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

# --- Scan scope: .yaml, composite actions (nested and directly under actions/), untracked, deleted-but-tracked. ---
mkdir -p "$T/.github/actions/x"
printf 'jobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n' > "$T/.github/workflows/b.yaml"
printf 'runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v5\n' > "$T/.github/actions/x/action.yml"
printf 'runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v5\n' > "$T/.github/actions/action.yml"
printf 'jobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n' > "$T/.github/workflows/d.yml"
git -C "$T" add -A
rm "$T/.github/workflows/d.yml"   # tracked, deleted from the work tree, not staged
printf 'jobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n' > "$T/.github/workflows/c.yml"   # untracked
errf="$N/err"
scan "$T" >/dev/null 2>"$errf" && fail "expected failure on scope tree"
out="$(cat "$errf")"
for want in .github/workflows/b.yaml:4: .github/actions/x/action.yml:4: .github/actions/action.yml:4: .github/workflows/c.yml:4:; do
  grep -qF "check-actions-pinned: $want" <<<"$out" || fail "$want not reported"
done
grep -qF "check-actions-pinned: note: .github/workflows/d.yml: tracked but missing from the work tree; skipped" <<<"$out" \
  || fail "d.yml missing-file note not printed"
grep -qF "skipped: this gate checks the work tree; the pushed commits may still contain it (ADR-0002 §2)" <<<"$out" \
  || fail "d.yml note lacks the work-tree wording"
if grep -qF "will be committed" <<<"$out"; then fail "d.yml note still claims the deletion is committed"; fi
if grep -F "d.yml" <<<"$out" | grep -qv "^check-actions-pinned: note: "; then fail "unlabelled line naming d.yml"; fi
scan "$T/.github" >/dev/null 2>&1 && fail "subdir run missed repo root"
out="$(scan "$N" 2>&1)" && fail "non-git dir should fail"
case "$out" in "check-actions-pinned: "*) ;; *) fail "non-git dir message not labelled: $out" ;; esac
for f in .github/workflows/b.yaml .github/actions/x/action.yml .github/actions/action.yml .github/workflows/c.yml; do
  sed 's|@v[0-9]*|@'"$sha"'|' "$T/$f" > "$T/$f.tmp" && mv "$T/$f.tmp" "$T/$f"
done

sed 's|actions/checkout@v4|actions/checkout@'"$sha"'  # v1|' "$wf" > "$wf.tmp" && mv "$wf.tmp" "$wf"
out="$(scan "$T" 2>&1)" || fail "fixed tree should pass: $out"
grep -qF "check-actions-pinned: OK (6 uses: in 5 files)" <<<"$out" || fail "unexpected OK line (d.yml must not count): $out"

# --- Per-case throwaway repos. ---
rn=0
newrepo() { rn=$((rn + 1)); repo="$R/r$rn"; mkdir -p "$repo/.github/workflows"; git -C "$repo" init -q; }
step() { printf 'jobs:\n  j:\n    steps:\n%s\n' "$1"; }   # a workflow whose only content is line 4

# F1: a non-ASCII file name must be scanned (git quotes it as "d\303\251ploy.yml" without -z).
newrepo
step '      - uses: actions/checkout@v4' > "$repo/.github/workflows/déploy.yml"
git -C "$repo" add -A
out="$(scan "$repo" 2>&1)" && fail "non-ASCII file name was skipped"
grep -qF "check-actions-pinned: .github/workflows/déploy.yml:4:" <<<"$out" || fail "déploy.yml:4 not reported: $out"

# F2: a failing git ls-files must fail the gate with a labelled message, never print OK.
newrepo
step '      - uses: actions/checkout@'"$sha" > "$repo/.github/workflows/a.yml"
git -C "$repo" add -A
printf 'garbage' > "$repo/.git/index"
out="$(scan "$repo" 2>&1)" && fail "corrupt index: scanner exited 0: $out"
grep -qF "check-actions-pinned: git ls-files failed" <<<"$out" || fail "corrupt index: no labelled message: $out"
if grep -qF "OK" <<<"$out"; then fail "corrupt index: printed OK: $out"; fi

# F3: `uses :` and a `!!str` tag on the key name the same key; tag-pinned is reported, SHA-pinned passes.
newrepo
for form in 'uses :' '- !!str uses:' '!!str uses :'; do
  case "$form" in -*) pre="      " ;; *) pre="    " ;; esac
  step "$pre$form actions/checkout@v4" > "$repo/.github/workflows/bad.yml"
  git -C "$repo" add -A
  out="$(scan "$repo" 2>&1)" && fail "'$form' tag-pinned passed: $out"
  grep -qF "check-actions-pinned: .github/workflows/bad.yml:4:" <<<"$out" || fail "'$form' not reported: $out"
  step "$pre$form actions/checkout@$sha" > "$repo/.github/workflows/bad.yml"
  git -C "$repo" add -A
  out="$(scan "$repo" 2>&1)" || fail "'$form' SHA-pinned failed: $out"
  grep -qF "OK (1 uses: in 1 files)" <<<"$out" || fail "'$form' SHA-pinned not counted: $out"
done

echo "check-actions-pinned selftest: OK (bash $ver)"
