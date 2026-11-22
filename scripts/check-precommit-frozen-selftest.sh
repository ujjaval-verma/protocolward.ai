#!/usr/bin/env bash
# Self-test for check-precommit-frozen.sh: an external hook rev that is not a full commit SHA with a
# "# frozen: v<tag>" comment must fail with its path:line, a frozen one must pass.
# The scanner always runs under "$BASH" (the interpreter running this file), never via its shebang,
# so a bash 3.2 run really exercises the scanner under bash 3.2.
# Fixtures never hold a literal CR, NEL, LS or PS byte: those are written with printf escapes at run time.
set -euo pipefail
# Builds throwaway repos with `git -C`; drop any inherited GIT_DIR/GIT_INDEX_FILE/...
# (git exports GIT_DIR to hooks and `rebase -x` in a linked worktree) so they cannot touch the caller's repo.
unset $(git rev-parse --local-env-vars)
here="$(cd "$(dirname "$0")" && pwd)"
R="$(mktemp -d)"   # parent of the per-case throwaway repos
N="$(mktemp -d)"   # a directory that is not a git work tree
trap 'rm -rf "${R:-}" "${N:-}"' EXIT
ver="${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"
cfg=.pre-commit-config.yaml
scan() { "$BASH" "$here/check-precommit-frozen.sh" "$@"; }
fail() { echo "check-precommit-frozen selftest: $*" >&2; exit 1; }
[[ -f $here/check-precommit-frozen.sh ]] || fail "scanner scripts/check-precommit-frozen.sh is missing"
sha=0123456789abcdef0123456789abcdef01234567
up=0123456789ABCDEF0123456789ABCDEF01234567
long=0123456789abcdef0123456789abcdef012345678
tab=$'\t'
unsup='unsupported YAML form'

rn=0
rc=0
out=""
newrepo() { rn=$((rn + 1)); repo="$R/r$rn"; mkdir -p "$repo"; git -C "$repo" init -q; }
run() { rc=0; out="$(scan "$@" 2>&1)" || rc=$?; }
reported() { grep -F "check-precommit-frozen: $cfg:$1: " <<<"$out" | grep -qF -- "$2"; }   # <line> <reason>
mk() { printf '%s\n' "$@" > "$repo/$cfg"; }
bad_case() {   # <label> <line> <reason> <config lines...>
  local label=$1 line=$2 why=$3
  shift 3
  newrepo
  mk "$@"
  run "$repo"
  [[ $rc -eq 1 ]] || fail "$label: expected exit 1, got $rc: $out"
  reported "$line" "$why" || fail "$label: $cfg:$line not reported with '$why': $out"
}
good_case() {   # <label> <config lines...>
  local label=$1
  shift
  newrepo
  mk "$@"
  run "$repo"
  [[ $rc -eq 0 ]] || fail "$label: expected exit 0, got $rc: $out"
  grep -qF "check-precommit-frozen: OK (" <<<"$out" || fail "$label: no OK line: $out"
}

# --- Every block-style bad form in one file: each bad line reported with its reason, no good line reported. ---
forms="$R/forms.yaml"
: > "$forms"
fl=0
badl=""    # newline-separated "line|reason" pairs
goodl=""   # line numbers that must not be reported
put()  { printf '%s\n' "$1" >> "$forms"; fl=$((fl + 1)); }
bad()  { put "$1"; badl="$badl$fl|$2"$'\n'; }
good() { put "$1"; goodl="$goodl$fl "; }
revbad() { local v=$1 why=$2; good '  - repo: https://h/x'; bad "    rev: $v" "$why"; }   # <rev value> <reason>
revok()  { local v=$1; good '  - repo: https://h/x'; good "    rev: $v"; }                    # <rev value>
notsha='not a full 40-hex lowercase commit SHA'
nofrozen='missing "# frozen: v<tag>" comment'
put  'repos:'
put  '  # a comment between items'
revbad 'v4.6.0'                                  "$notsha"
revbad 'main'                                    "$notsha"
revbad 'de0fac2'                                 "$notsha"
revbad "$up  # frozen: v1"                       "$notsha"
revbad "$long  # frozen: v1"                     "$notsha"
revbad '"v4.6.0"  # frozen: v4.6.0'              "$notsha"
revbad ''                                        'rev (empty)'
revbad "$sha"                                    "$nofrozen"
revbad "$sha  # v4.6.0"                          "$nofrozen"
revbad "$sha  # frozen: 4.6.0"                   "$nofrozen"
revbad "$sha  # frozen:"                         "$nofrozen"
revbad "$sha # frozen: v1 extra"                 "$nofrozen"
revbad "\"$sha"                                  'rev: unterminated quote'
revbad "\"$sha\" junk"                           'rev: unexpected text after the closing quote'
revbad "\"$sha\"# frozen: v1"                    'rev: unexpected text after the closing quote'
good '  - repo: https://h/x'
bad  '    rev:'                                  'rev: value continues on the next line'
put  "      $sha"
bad  '  - repo: https://h/norev'                 'repo https://h/norev: no rev: line'
good '  - repo: https://h/dup'
good "    rev: $sha  # frozen: v1"
bad  '    rev : v4.6.0'                          'duplicate rev:'
good '  - repo: local'
bad  '    repo : https://evil'                   'duplicate repo:'
bad  "  - rev: $sha  # frozen: v1"               'item has no repo: line'
bad  '    "repo": https://h/q'                   "$unsup"
good '  - repo: https://h/qk'
good "    rev: $sha  # frozen: v1"
bad  '    "name": x'                             "$unsup"
bad  '  - <<: *base'                             "$unsup"
bad  '  - *x'                                    "$unsup"
bad  '  -'                                       "$unsup"
bad  "  -${tab}repo: https://h/t"                "$unsup"
good '    rev: v4.6.0'   # skipped: the item opener is refused, so its lines are not checked
bad  '  -repo: x'                                "$unsup"
good '    rev: v4.6.0'
good '  - repo: https://h/qq'
good "    rev: $sha  # frozen: v1"
bad  '    ? rev'                                 "$unsup"
bad  '    : v4.6.0'                              "$unsup"
good '  - repo: https://h/nc'
good "    rev: $sha  # frozen: v1"
bad  '    justtext'                              "$unsup"
bad  '  - repo: local'                           'repo: value continues on the next line'
put  '      more'
good '  - repo: local#x'
bad  '    rev: v4.6.0'                           "$notsha"
# Good lines (all in one block with the bad ones above; none may be reported).
revok "$sha  # frozen: v4.6.0"
revok "\"$sha\"  # frozen: v4.6.0"
revok "'$sha'  # frozen: v4.6.0"
revok "$sha  #frozen:v1"
good '  - repo: https://h/space'
good "    rev :  $sha  # frozen: v1"
good '  -   repo: https://h/dash3'
good "      rev: $sha  # frozen: v1"
good "  - rev: $sha  # frozen: v1"
good '    repo: https://h/revfirst'
put  ''
good '  - repo: local'
good '    hooks:'
good '      - id: x'
good '        rev: v4.6.0'
good '  - repo: "local"'
good '  - repo: local  # c'
good '  - repo: meta  # c'
put  '# trailing comment'
put  'ci:'
put  '  autofix_prs: false'
newrepo
cp "$forms" "$repo/$cfg"
run "$repo"
[[ $rc -eq 1 ]] || fail "forms file: expected exit 1, got $rc: $out"
while IFS='|' read -r ln why; do
  [[ -n $ln ]] || continue
  reported "$ln" "$why" || fail "forms file: $cfg:$ln not reported with '$why': $out"
done <<<"$badl"
for ln in $goodl; do
  if grep -qF "check-precommit-frozen: $cfg:$ln: " <<<"$out"; then fail "forms file: good line $ln flagged: $out"; fi
done
grep -qF "check-precommit-frozen: hint: " <<<"$out" || fail "forms file: hint line missing: $out"
lf_out="$out"
# CRLF copy of the bad file: same reports on the same line numbers.
newrepo
while IFS= read -r l; do printf '%s\r\n' "$l"; done < "$forms" > "$repo/$cfg"
run "$repo"
[[ $rc -eq 1 ]] || fail "forms file (CRLF): expected exit 1, got $rc"
[[ $out == "$lf_out" ]] || fail "forms file (CRLF): reports differ from the LF file: $out"

# --- The debug hook names the bash that runs the scanner. ---
newrepo
mk 'repos:'
dbg="$(CHECK_PRECOMMIT_FROZEN_DEBUG=1 scan "$repo" 2>&1 || true)"
grep -qF "check-precommit-frozen: debug: bash $ver" <<<"$dbg" || fail "scanner did not run under bash $ver: $dbg"

# --- A good file: counts, CRLF copy, subdirectory run. ---
good=(
  'repos:'
  '  - repo: https://h/a'
  "    rev: $sha  # frozen: v4.6.0"
  '  - repo: https://h/b'
  "    rev: '$sha'  # frozen: v1"
  '  - repo: local'
  '    hooks:'
  '      - id: x'
  '  - repo: meta'
  '    hooks:'
  '      - id: check-hooks-apply'
)
newrepo
mk "${good[@]}"
run "$repo"
[[ $rc -eq 0 ]] || fail "good file: expected exit 0, got $rc: $out"
[[ $out == "check-precommit-frozen: OK (2 external repos frozen, 2 local/meta)" ]] || fail "good file: unexpected output: $out"
mkdir -p "$repo/sub"
run "$repo/sub"
[[ $rc -eq 0 ]] || fail "subdirectory run missed the repo root: $out"
newrepo
for l in "${good[@]}"; do printf '%s\r\n' "$l"; done > "$repo/$cfg"
run "$repo"
[[ $rc -eq 0 ]] || fail "good file (CRLF): expected exit 0, got $rc: $out"

# --- The Dependabot-shaped line: it replaces the SHA and the version in the frozen comment, spacing kept. ---
dep='    rev: 2c9f875913ee60ca25ce70243dc24d5b6415598c  # frozen: v4.6.0'
newrepo
mk 'repos:' '  - repo: https://github.com/pre-commit/pre-commit-hooks' "$dep" '    hooks:' '      - id: check-yaml'
run "$repo"
[[ $rc -eq 0 ]] || fail "Dependabot-shaped file (before): expected exit 0, got $rc: $out"
dep2="${dep/2c9f875913ee60ca25ce70243dc24d5b6415598c/fb24a639f7c938759fe56eeebbb7713b69d60494}"
dep2="${dep2/v4.6.0/v4.7.0}"
[[ $dep2 == '    rev: fb24a639f7c938759fe56eeebbb7713b69d60494  # frozen: v4.7.0' ]] || fail "Dependabot substitution went wrong: $dep2"
mk 'repos:' '  - repo: https://github.com/pre-commit/pre-commit-hooks' "$dep2" '    hooks:' '      - id: check-yaml'
run "$repo"
[[ $rc -eq 0 ]] || fail "Dependabot-shaped file (after): expected exit 0, got $rc: $out"

# --- Whole-file cases, one throwaway repo each. ---
bad_case 'flow repos:' 1 "$unsup" 'repos: [ {repo: https://h/a, rev: v4.6.0} ]'
if grep -qF 'no top-level repos: block' <<<"$out"; then fail "flow repos: also reported no top-level block: $out"; fi
bad_case 'anchored repos:' 1 "$unsup" 'repos: &a' '  - repo: https://h/a' '    rev: v4.6.0'
bad_case 'quoted "repos":' 1 'no top-level repos: block' '"repos":' '  - repo: https://h/a' "    rev: $sha  # frozen: v1"
bad_case 'quoted "repos": own line' 1 "$unsup" '"repos":' '  - repo: https://h/a' "    rev: $sha  # frozen: v1"
bad_case 'no repos:' 1 'no top-level repos: block' 'foo: bar'
bad_case 'empty file' 1 'no top-level repos: block' ''
good_case 'items at indent 0' 'repos:' '- repo: https://h/a' "  rev: $sha  # frozen: v1" 'other: x'
bad_case 'items at indent 0, bad rev' 3 "$notsha" 'repos:' '- repo: https://h/a' '  rev: v4.6.0' 'other: x'
bad_case 'second repos: block' 4 'duplicate repos:' \
  'repos:' '  - repo: https://h/a' "    rev: $sha  # frozen: v1" \
  'repos:' '  - repo: https://h/b' '    rev: v4.6.0'
bad_case 'second repos: block with a flow value' 4 'duplicate repos:' \
  'repos:' '  - repo: https://h/a' "    rev: $sha  # frozen: v1" 'repos: []'
bad_case 'second block keyed "repos":' 4 "$unsup" \
  'repos:' '  - repo: https://h/a' "    rev: $sha  # frozen: v1" \
  '"repos":' '  - repo: https://h/b' '    rev: v4.6.0'
bad_case 'second block keyed !!str repos:' 4 "$unsup" \
  'repos:' '  - repo: https://h/a' "    rev: $sha  # frozen: v1" \
  '!!str repos:' '  - repo: https://h/b' '    rev: v4.6.0'
bad_case 'second block keyed ? repos' 4 "$unsup" \
  'repos:' '  - repo: https://h/a' "    rev: $sha  # frozen: v1" \
  '? repos' ':' '  - repo: https://h/b' '    rev: v4.6.0'
reported 5 "$unsup" || fail "second block keyed ? repos: the : line 5 not reported: $out"
bad_case 'repos: then a non-item line' 2 "$unsup" 'repos:' '  foo: bar'
bad_case 'repos: then a top-level key' 1 'repos: has no items' 'repos:' 'other: x'
bad_case 'repos: at end of file' 1 'repos: has no items' 'repos:' '' '# nothing'
bad_case 'hooks: before the first item' 2 "$unsup" 'repos:' '  hooks: []'

# --- A last line without a trailing LF is scanned. ---
newrepo
printf 'repos:\n  - repo: https://h/a\n    rev: v4.6.0' > "$repo/$cfg"
run "$repo"
[[ $rc -eq 1 ]] || fail "no trailing LF: expected exit 1, got $rc: $out"
reported 3 "$notsha" || fail "no trailing LF: $cfg:3 not reported: $out"

# --- Line breaks other than LF hide content from a line scanner: refused at their own line. ---
hidden() {   # <label> <printf format of the line that hides> <expected line is 4>
  newrepo
  {
    printf 'repos:\n'
    printf '  - repo: https://h/ok\n'
    printf '    rev: %s  # frozen: v1\n' "$sha"
    printf "$2"
  } > "$repo/$cfg"
  run "$repo"
  [[ $rc -eq 1 ]] || fail "$1: expected exit 1, got $rc: $out"
  reported 4 'line break character (CR, NEL, LS or PS) inside a line' || fail "$1: $cfg:4 not reported: $out"
}
hidden 'CR in a comment'  '  # note\015  - repo: https://h/hid\n    rev: v4.6.0\n'
hidden 'LS in a comment'  '  # note\342\200\250  - repo: https://h/hid\n    rev: v4.6.0\n'
hidden 'PS in a comment'  '  # note\342\200\251  - repo: https://h/hid\n    rev: v4.6.0\n'
hidden 'CR after hooks:'  '    hooks:\015    rev: v4.6.0\n'
hidden 'NEL after hooks:' '    hooks:\302\205    rev: v4.6.0\n'

# --- Setup errors: labelled message, exit 1, and no autoupdate hint. ---
newrepo
run "$repo"
[[ $rc -eq 1 ]] || fail "missing config: expected exit 1, got $rc: $out"
grep -qF "check-precommit-frozen: " <<<"$out" || fail "missing config: message not labelled: $out"
grep -qF "$cfg: not found" <<<"$out" || fail "missing config: message does not name the file: $out"
if grep -qF 'hint:' <<<"$out"; then fail "missing config: hint line printed: $out"; fi
run "$N"
[[ $rc -eq 1 ]] || fail "non-git dir: expected exit 1, got $rc: $out"
grep -qF "check-precommit-frozen: not a git work tree: $N" <<<"$out" || fail "non-git dir: message not labelled: $out"
if grep -qF 'hint:' <<<"$out"; then fail "non-git dir: hint line printed: $out"; fi

# --- The hint line says what to run, and the exit status is exactly 1. ---
newrepo
mk 'repos:' '  - repo: https://h/a' '    rev: v4.6.0'
run "$repo"
[[ $rc -eq 1 ]] || fail "bad file: expected exit 1, got $rc"
grep -qF "check-precommit-frozen: hint: for a rev, run pre-commit autoupdate --freeze" <<<"$out" || fail "bad file: hint line missing: $out"

echo "check-precommit-frozen selftest: OK (bash $ver)"
