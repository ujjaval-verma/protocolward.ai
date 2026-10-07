#!/usr/bin/env bash
# Fail if the tracked tree carries anything that must not reach the public
# repository (ADR-0007). Runs in `make check`. Searches tracked files only.
# Usage: scripts/check-public.sh [repo-dir]   (default: this repo)
set -euo pipefail
dir="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
# Always scan the whole repo, even when invoked from a subdirectory.
root="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)" || {
  echo "check-public: $dir is not inside a git work tree (it scans tracked files only)" >&2
  exit 1
}
cd "$root"
# An empty index (e.g. a fresh `git init` before `git add -A`) must not pass vacuously.
[[ -n "$(git ls-files | head -n1)" ]] || {
  echo "check-public: no tracked files under $root (run git add -A first)" >&2
  exit 1
}
# The gate and its self-test are exempt from the content rules because they
# necessarily spell out the forbidden patterns and fixtures.
self=':(exclude)scripts/check-public.sh'
selftest=':(exclude)scripts/check-public-selftest.sh'
fail=0

rule() { # rule "<label>" <git grep args...>
  local label="$1"; shift
  local hits
  hits="$(git grep -nI "$@" || true)"
  if [[ -n "$hits" ]]; then
    printf 'check-public: %s\n%s\n\n' "$label" "$hits" >&2
    fail=1
  fi
}

# Eval fixtures hold real popular domain names (Majestic sample); a benign
# name like investors.com is data, not a leak.
rule "private or internal-only reference" -iE 'toptal|greenmile|investor|confidential|ai/docs/ujjaval' \
  -- . "$self" "$selftest" ':(exclude)testdata/eval/*.jsonl'
rule "price figure in public copy" -E '(^|[[:space:](])[$€£][0-9]|[0-9] ?(USD|EUR|GBP)|(USD|EUR|GBP) ?[0-9]|[0-9] ?(per |/ ?)(month|mo|year|yr)' \
  -- . "$self" "$selftest" ':(exclude)go.sum' ':(exclude)testdata/eval/*.jsonl'
# Public-copy file types never legitimately hold a dollar amount, so no
# context is required there (tag-adjacent, quoted or bold prices).
rule "price figure in public copy" -E '[$€£][0-9]' \
  -- '*.md' '*.html' '*.txt' '*.yml' '*.yaml' '*.json' '*.js' '*.mjs' '*.css' '*.toml' \
  "$self" "$selftest" ':(exclude)go.sum' ':(exclude)testdata/eval/*.jsonl'
rule "citation of an unpublished design note" -E 'superpowers/(specs|plans|reviews)/[0-9]{4}-|\.superpowers/sdd/' -- . "$self" "$selftest"
# Slice-spec section cites ("spec §3 S2") point at a gitignored design note.
rule "citation of an unpublished spec section in Go" -E '[Ss]pec (§|D)[0-9]' -- '*.go' "$self" "$selftest"
# Any tracked text (Go comments included), not only Markdown.
rule "commit hash that dies with the squash" -E '`[0-9a-f]{7,12}`|/commit/[0-9a-f]{7,40}|[Cc]o[m]mit [0-9a-f]{7,40}' -- . "$self" "$selftest" ':(exclude)go.sum' ':(exclude)testdata/eval/*.jsonl'
rule "pre-beta module path" -E 'github\.com/(protocol-ward|ujjaval-verma/protocol-ward)([^A-Za-z0-9_-]|$)' -- . "$self" "$selftest"

if (( fail )); then
  echo "check-public: FAIL (see ADR-0007)" >&2
  exit 1
fi
echo "check-public: OK"
