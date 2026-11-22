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
put  '  next-job:'   # keeps the steps below from reading as a continuation of the job-level uses:
good "      - uses: docker://alpine@sha256:$dig"
bad  '      - uses: docker://alpine:3.20'                              'not pinned by @sha256:'
put  '  other-job:'
bad  '      - {uses: actions/checkout@v4}'                             'not in block form'
bad  "      - {name: a, uses: \"owner/repo@$sha\"}"                   'not in block form'
bad  "      - \"uses\": owner/repo@$sha"                              'not in block form'
bad  "      - 'uses' : actions/checkout@v4"                           'not in block form'
bad  "      - - uses: owner/repo@$sha"                                'not in block form'
bad  '      - run: echo uses: x'                                      'not in block form'
bad  '      - name: x  # uses: y'                                     'not in block form'
bad  'step-anchor: &s {uses: actions/checkout@v4}'                    'not in block form'
put  '  other-job2:'
good '      statuses: write'
good '      - name: Report causes: x'
good '      - with: { ref: main }'
put  '  more-job:'
bad  '      ? uses'                                                   'explicit ? mapping key'
bad  '      - { ? uses'                                               'explicit ? mapping key'
put  '          : actions/checkout@v4 }'
bad  '      - { ? *k : actions/checkout@v4 }'                         'explicit ? mapping key'
bad  '      - *k : actions/checkout@v4'                               'alias used as a mapping key'
bad  '      - "u\x73es": actions/checkout@v4'                         'escape sequence in a double-quoted mapping key'
bad  '      - !!str "u\x73es": actions/checkout@v4'                   'escape sequence in a double-quoted mapping key'
bad  '      - &a "u\x73es": actions/checkout@v4'                      'escape sequence in a double-quoted mapping key'
bad  '      - {!!str "u\x73es": actions/checkout@v4}'                 'escape sequence in a double-quoted mapping key'
bad  "              ? 'pr'"                                              'explicit ? mapping key'
bad  "              ? 'pr'"                                              'if this line is script or text inside a block scalar'
bad  '          **Status:** green'                                      'alias used as a mapping key'
bad  '          **Status:** green'                                      'if this line is script or text inside a block scalar'
bad  '          "a\tb": x'                                              'escape sequence in a double-quoted mapping key'
bad  '          "a\tb": x'                                              'if this line is script or text inside a block scalar'
good '          echo "**Status:** ok"'
good '          : "${X:?msg}"'
good '      - name: "a\tb"'
good '      - !!str "a\tb"'
put  '  last-job:'
printf '      - name: a\015      - uses: actions/checkout@v4\n' >> "$forms"; fl=$((fl + 1)); badl="$badl$fl|line break other than LF"$'\n'
printf '      - name: a\342\200\250- uses: x@v4\n' >> "$forms"; fl=$((fl + 1)); badl="$badl$fl|line break other than LF"$'\n'
printf '      - name: a\302\205- uses: x@v4\n' >> "$forms"; fl=$((fl + 1)); badl="$badl$fl|line break other than LF"$'\n'
printf '      - name: a\342\200\251- uses: x@v4\n' >> "$forms"; fl=$((fl + 1)); badl="$badl$fl|line break other than LF"$'\n'
put  'x-step2: &t'
bad  '  uses: actions/checkout@v4'                                    'not pinned to a full 40-hex'
put  'z-job:'
good '      - <<: *t'
put  '  tail-job:'
put  '    steps: [ {name: a,'
bad  "        uses: owner/repo@$sha }, {uses: actions/checkout@v4} ]"  'text after the uses: value'
put  '  tail-job2:'
put  '      - {name: a,'
bad  "        uses: owner/repo@$sha }"                                 'text after the uses: value'
put  '  tail-job3:'
good "      - uses: owner/repo@$sha  # v1"
bad  '        uses: ./x},{"uses":actions/checkout@v4}]'                'text after the uses: value'
bad  '        uses: "./x\" # "}, {"uses": "actions/checkout@v4"}]'     'escape sequence in a double-quoted uses: value'
printf '      - uses: owner/repo@%s  # v1\r\n' "$sha" >> "$forms"; fl=$((fl + 1)); goodl="$goodl$fl "
git -C "$T" add -A
out="$(scan "$T" 2>&1)" && fail "expected failure on forms tree"
while IFS='|' read -r ln why; do
  [[ -n $ln ]] || continue
  grep -F "check-actions-pinned: .github/workflows/forms.yml:$ln:" <<<"$out" | grep -qF "$why" \
    || fail "forms.yml:$ln not reported with '$why'"
done <<<"$badl"
for ln in $goodl; do
  if grep -qF "forms.yml:$ln:" <<<"$out"; then fail "good line forms.yml:$ln flagged: $out"; fi
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
expect_bad() {   # <workflow body line(s) from line 4> <label> [message fragment]
  newrepo
  step "$1" > "$repo/.github/workflows/a.yml"
  git -C "$repo" add -A
  out="$(scan "$repo" 2>&1)" && fail "$2: scanner passed: $out"
  grep -qF "check-actions-pinned: .github/workflows/a.yml:4:" <<<"$out" || fail "$2: not reported at a.yml:4: $out"
  if [[ -n ${3:-} ]]; then grep -qF "$3" <<<"$out" || fail "$2: message lacks '$3': $out"; fi
}
expect_good() {
  newrepo
  step "$1" > "$repo/.github/workflows/a.yml"
  git -C "$repo" add -A
  out="$(scan "$repo" 2>&1)" || fail "$2: scanner failed: $out"
  grep -qF "OK (1 uses: in 1 files)" <<<"$out" || fail "$2: not counted as one use: $out"
}

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

# N2: strict quoting. Only whitespace or a `# comment` may follow a closing quote; a value may not continue on the next line.
expect_bad "      - uses: \"actions/checkout@$sha\" junk" 'text after double quote'
expect_bad "      - uses: \"actions/checkout@$sha\"# c" 'comment without space after quote'
expect_bad "      - uses: 'actions/checkout@$sha' junk" 'text after single quote'
expect_bad "      - uses: 'actions/checkout@$sha''x'" "'' escape after the sha"
expect_bad "      - uses: 'actions/checkout@v4''@$sha'" "'' escape inside the value"
expect_bad $'      - uses: actions/checkout@'"$sha"$'\n          v4' 'plain scalar continuation line' 'continues on the next line'
expect_good "      - uses: \"actions/checkout@$sha\"   # c" 'double quote then comment'
expect_good "      - uses: 'actions/checkout@$sha' # c" 'single quote then comment'
expect_good "      - uses: 'actions/checkout@$sha'  " 'single quote then trailing spaces'
expect_good $'      - uses: actions/checkout@'"$sha"$'\n        # more indented comment\n        with:\n          x: y' 'sibling key and comment after uses'

# N3: byte semantics. An invalid UTF-8 byte on a uses: line must not hide it, even in a UTF-8 locale.
newrepo
printf 'jobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4 # \377\n' > "$repo/.github/workflows/a.yml"
git -C "$repo" add -A
for loc in en_US.UTF-8; do
  out="$(LC_ALL=$loc scan "$repo" 2>&1)" && fail "invalid UTF-8 byte hid a bad uses: (LC_ALL=$loc): $out"
  grep -qF "check-actions-pinned: .github/workflows/a.yml:4:" <<<"$out" || fail "invalid UTF-8 line not reported (LC_ALL=$loc): $out"
done

# N4: expressions, docker digest shape, a single-quoted good line, the hint line and the exact exit status.
expect_bad '      - uses: ${{ matrix.action }}' 'expression ref' 'not pinned to a full 40-hex'
expect_bad "      - uses: docker://alpine@sha256:${up}${up:0:24}" 'uppercase docker digest' 'not pinned by @sha256:'
expect_bad "      - uses: docker://alpine@sha256:${dig:1}" '63-hex docker digest' 'not pinned by @sha256:'
expect_good "      - uses: 'actions/checkout@$sha'" 'single-quoted good line'
newrepo
step '      - uses: actions/checkout@v4' > "$repo/.github/workflows/a.yml"
git -C "$repo" add -A
rc=0
out="$(scan "$repo" 2>&1)" || rc=$?
[[ $rc -eq 1 ]] || fail "bad tree: expected exit 1, got $rc"
grep -qF "check-actions-pinned: hint: pin by full commit SHA" <<<"$out" || fail "bad tree: hint line missing: $out"

echo "check-actions-pinned selftest: OK (bash $ver)"
