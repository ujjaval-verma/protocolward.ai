#!/usr/bin/env bash
# Fail if an external pre-commit hook repo in .pre-commit-config.yaml is not frozen to a commit SHA.
# Every external hook rev must be a full 40-hex commit SHA followed by a "# frozen: v<tag>" comment
# (what `pre-commit autoupdate --freeze` writes and what Dependabot's updater keeps; ADR-0002 §1).
# Plain bash line scanner, no Python or pre-commit needed. Local and meta repos need no rev.
# It fails closed on the block-style forms it reads; it does not catch a deliberately obscured spelling that ends the
# repos block early (see the accepted residuals in ADR-0002 §2, threat model of the issue #52 note).
# Usage: scripts/check-precommit-frozen.sh [repo-dir]   (default: this repo)
# Plain bash 3.2-compatible: regexes live in variables, no mapfile, no associative arrays.
set -euo pipefail
export LC_ALL=C   # byte semantics, so a stray byte cannot make a regex skip a line
dir="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
if [[ "${CHECK_PRECOMMIT_FROZEN_DEBUG:-}" == 1 ]]; then
  echo "check-precommit-frozen: debug: bash ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}" >&2
fi
root="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)" || {
  echo "check-precommit-frozen: not a git work tree: $dir (pass a repository directory)" >&2
  exit 1
}
cfg=.pre-commit-config.yaml
path="$root/$cfg"
if [[ ! -f $path ]]; then
  echo "check-precommit-frozen: $path: not found (restore .pre-commit-config.yaml)" >&2
  exit 1
fi

re_blank='^[[:space:]]*(#.*)?$'                          # blank or comment line
re_ind='^([[:space:]]*)'
re_badfirst="^[\"'?:!&*{[<]"                              # column-0 first characters that can spell the repos key another way
re_reposkey='^repos[[:space:]]*:'
re_reposplain='^repos[[:space:]]*:[[:space:]]*(#.*)?$'
re_sp='^([ ]*)(.*)$'
re_dq='^"([^"]*)"'
re_sq="^'([^']*)'"
re_dqfull='^"(.*)"$'
re_sqfull="^'(.*)'\$"
re_tail='^([[:space:]]+#.*|[[:space:]]*)$'               # after a closing quote: only whitespace or a # comment
re_hex='^[0-9a-f]{40}$'
re_frozen='^[[:space:]]+#[[:space:]]*frozen:[[:space:]]*v[^[:space:]]+[[:space:]]*$'
unsup='unsupported YAML form; write each repo as a block mapping'

bad=0
ext=0
lm=0
report() { printf 'check-precommit-frozen: %s:%s: %s\n' "$cfg" "$1" "$2" >&2; bad=1; }

# Read every line; one trailing CR is stripped (CRLF files), a last line without LF is kept.
L=()
n=0
while IFS= read -r line || [[ -n $line ]]; do
  n=$((n + 1))
  L[n]="${line%$'\r'}"
done < "$path"

# Per line: B = blank or comment, IND = number of leading whitespace characters.
B=()
IND=()
first=0
firstplain=0
i=1
while (( i <= n )); do
  l="${L[i]}"
  if [[ $l == *$'\r'* || $l == *$'\xc2\x85'* || $l == *$'\xe2\x80\xa8'* || $l == *$'\xe2\x80\xa9'* ]]; then
    report "$i" "line break character (CR, NEL, LS or PS) inside a line (use LF line endings)"
  fi
  [[ $l =~ $re_ind ]]
  IND[i]="${#BASH_REMATCH[1]}"
  if [[ $l =~ $re_blank ]]; then
    B[i]=1
  else
    B[i]=0
    if [[ $l =~ $re_badfirst ]]; then
      report "$i" "$unsup"
    fi
    if [[ $l =~ $re_reposkey ]]; then
      if (( first == 0 )); then
        first=$i
        if [[ $l =~ $re_reposplain ]]; then
          firstplain=1
        else
          report "$i" "$unsup"
        fi
      else
        report "$i" "duplicate repos: (keep one repos: block)"
      fi
    fi
  fi
  i=$((i + 1))
done
if (( first == 0 )); then
  report 1 "no top-level repos: block (write repos: at column 0)"
fi

# next_nc <line>: sets NC to the next non-blank, non-comment line after <line>, or 0.
NC=0
next_nc() {
  local from=$1 k
  k=$((from + 1))
  while (( k <= n )); do
    if (( ! B[k] )); then NC=$k; return; fi
    k=$((k + 1))
  done
  NC=0
}

# strip_comment <text>: sets SC to the text without a trailing comment (a # at the start or after whitespace).
SC=""
strip_comment() {
  local s="$1" acc="" head
  while [[ $s == *'#'* ]]; do
    head="${s%%#*}"
    if [[ ( -z $acc && -z $head ) || $head == *[[:space:]] ]]; then
      SC="$acc$head"
      return
    fi
    acc="$acc$head#"
    s="${s#*#}"
  done
  SC="$acc$s"
}

trim() {   # sets T to the text without surrounding whitespace
  T="${1#"${1%%[![:space:]]*}"}"
  T="${T%"${T##*[![:space:]]}"}"
}

# check_rev <line> <value> <key column>
check_rev() {
  local ln=$1 v="$2" kcol=$3 tok tail
  v="${v%"${v##*[![:space:]]}"}"
  if [[ -z $v || $v == '#'* ]]; then
    next_nc "$ln"
    if (( NC > 0 && IND[NC] > kcol )); then
      report "$ln" "rev: value continues on the next line"
    else
      report "$ln" "rev (empty): not a full 40-hex lowercase commit SHA"
    fi
    return
  fi
  if [[ $v == \"* || $v == \'* ]]; then
    if [[ $v =~ $re_dq || $v =~ $re_sq ]]; then
      tok="${BASH_REMATCH[1]}"
      tail="${v:${#BASH_REMATCH[0]}}"
      if [[ ! $tail =~ $re_tail ]]; then
        report "$ln" "rev: unexpected text after the closing quote"
        return
      fi
    else
      report "$ln" "rev: unterminated quote"
      return
    fi
  else
    tok="${v%%[[:space:]]*}"
    tail="${v:${#tok}}"
  fi
  if [[ ! $tok =~ $re_hex ]]; then
    report "$ln" "rev ${tok:-(empty)}: not a full 40-hex lowercase commit SHA"
  elif [[ ! $tail =~ $re_frozen ]]; then
    report "$ln" "rev $tok: missing \"# frozen: v<tag>\" comment"
  fi
}

ii=0
# do_item <first line> <last line>
do_item() {
  local s=$1 e=$2 rest sp op kc i t key val k
  local repo_n=0 rev_n=0 rline=0 rval="" rcont=0 islocal=0 failed=0
  local RL=() RV=()
  rest="${L[s]:$((ii + 1))}"
  if [[ -z $rest || $rest != ' '* ]]; then
    report "$s" "$unsup"
    return
  fi
  [[ $rest =~ $re_sp ]]
  sp="${#BASH_REMATCH[1]}"
  op="${BASH_REMATCH[2]}"
  case $op in
    '' | '{'* | '['* | '&'* | '*'* | '!'* | '"'* | "'"* | '<<'*)
      report "$s" "$unsup"
      return
      ;;
  esac
  kc=$((ii + 1 + sp))
  i=$s
  while (( i <= e )); do
    if (( i == s )); then
      t="$op"
    elif (( ! B[i] && IND[i] == kc )); then
      t="${L[i]:$kc}"
      if [[ $t == '-'* ]]; then i=$((i + 1)); continue; fi   # sequence entry of the previous key
    else
      i=$((i + 1))
      continue
    fi
    case $t in
      '"'* | "'"* | '&'* | '*'* | '!'* | '<<'* | '?'* | ':'*)
        report "$i" "$unsup"
        i=$((i + 1))
        continue
        ;;
    esac
    if [[ $t != *:* ]]; then
      report "$i" "$unsup"
      i=$((i + 1))
      continue
    fi
    key="${t%%:*}"
    key="${key%"${key##*[![:space:]]}"}"
    val="${t#*:}"
    val="${val#"${val%%[![:space:]]*}"}"
    case $key in
      repo)
        repo_n=$((repo_n + 1))
        if (( repo_n == 2 )); then
          report "$i" "duplicate repo: (keep one repo: per item)"
        elif (( repo_n == 1 )); then
          rline=$i
          rval="$val"
        fi
        next_nc "$i"
        if (( NC > 0 && IND[NC] > kc )); then
          report "$i" "repo: value continues on the next line"
          if (( repo_n == 1 )); then rcont=1; fi
        fi
        ;;
      rev)
        rev_n=$((rev_n + 1))
        if (( rev_n >= 2 )); then
          report "$i" "duplicate rev: (keep one rev: per repo item)"
        fi
        RL[rev_n]=$i
        RV[rev_n]="$val"
        ;;
    esac
    i=$((i + 1))
  done
  if (( repo_n == 0 )); then
    report "$s" "item has no repo: line (start each item with - repo:)"
  else
    strip_comment "$rval"
    trim "$SC"
    rval="$T"
    if [[ $rval =~ $re_dqfull || $rval =~ $re_sqfull ]]; then rval="${BASH_REMATCH[1]}"; fi
    if (( ! rcont )) && [[ $rval == local || $rval == meta ]]; then islocal=1; fi
  fi
  if (( islocal )); then
    lm=$((lm + 1))
    return
  fi
  ext=$((ext + 1))
  if (( repo_n > 0 && rev_n == 0 )); then
    report "$rline" "repo ${rval:-(empty)}: no rev: line"
  fi
  k=1
  while (( k <= rev_n )); do
    check_rev "${RL[k]}" "${RV[k]}" "$kc"
    k=$((k + 1))
  done
}

# Walk the first repos: block when it is a plain `repos:` line.
if (( firstplain )); then
  next_nc "$first"
  j=$NC
  if (( j == 0 )); then
    report "$first" "repos: has no items; add at least one repo item"
  else
    ii="${IND[j]}"
    if [[ ${L[j]:$ii:1} != '-' ]]; then
      if (( ii == 0 )); then
        report "$first" "repos: has no items; add at least one repo item"
      else
        report "$j" "$unsup"
      fi
    else
      starts=()
      ns=0
      k=$j
      while (( k <= n )); do
        if (( ! B[k] )); then
          if (( IND[k] < ii )) || { (( IND[k] == ii )) && [[ ${L[k]:$ii:1} != '-' ]]; }; then
            break
          fi
          if (( IND[k] == ii )); then
            ns=$((ns + 1))
            starts[ns]=$k
          fi
        fi
        k=$((k + 1))
      done
      m=1
      while (( m <= ns )); do
        if (( m < ns )); then e=$((starts[m + 1] - 1)); else e=$((k - 1)); fi
        do_item "${starts[m]}" "$e"
        m=$((m + 1))
      done
    fi
  fi
fi

if (( bad )); then
  echo "check-precommit-frozen: hint: for a rev, run pre-commit autoupdate --freeze, or pin rev: <40 hex>  # frozen: vX.Y.Z (ADR-0002 §1)" >&2
  exit 1
fi
echo "check-precommit-frozen: OK ($ext external repos frozen, $lm local/meta)"
