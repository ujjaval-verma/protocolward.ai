#!/usr/bin/env bash
# Self-test for check-public.sh: every rule must fire on its own bad fixture
# (matched by rule label, not just filename), the Majestic-derived eval data
# must be exempt, benign shell/Makefile dollars must not trip the price rule,
# and a clean tree must pass.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T" "${B:-}"' EXIT
git -C "$T" init -q
mkdir -p "$T/docs" "$T/testdata/eval" "$T/sub"
printf 'Pro costs $9/mo\n'                              > "$T/docs/a.md"
printf '// see docs/superpowers/specs/2026-01-01-x.md\n' > "$T/b.go"
printf 'fixed in `abc1234`\n'                           > "$T/docs/c.md"
printf 'Investor update\n'                              > "$T/d.txt"
printf '// fixed in commit abc1234def\n'                 > "$T/e.go"
printf '// default on (spec §3 S2)\n'                    > "$T/f.go"
printf '// flag-only (spec D7)\n'                        > "$T/g.go"
printf '# 12 EUR per year\n'                             > "$T/h.sh"
printf 'import "github.com/protocol-ward/ward/pkg/x"\n' > "$T/i.go"
printf '{"name":"investors.com","label":"benign"}\n'     > "$T/testdata/eval/x.jsonl"
printf 'echo "$1" $(date)\nfoo:\n\t@echo $$HOME\n'       > "$T/ok.sh"
mkdir -p "$T/site" "$T/deploy"
printf '<span>$12</span>\n'                            > "$T/site/p.html"
printf 'price: "$9"\n'                                 > "$T/deploy/p.yaml"
printf '{"plan":"$9"}\n'                               > "$T/deploy/p.json"
printf 'Pro: **$9**\n'                                 > "$T/docs/q.md"
printf '[spec](../superpowers/specs/2026-10-05-x.md)\n' > "$T/docs/n2a.md"
mkdir -p "$T/notes"
printf 'see .superpowers/sdd/2026-10-05-x/progress.md\n'    > "$T/notes/n2b.md"
printf 'see github.com/protocol-ward\n'                    > "$T/docs/n6a.md"
printf 'clone github.com/ujjaval-verma/protocol-ward.git\n' > "$T/docs/n6b.md"
printf 'ok github.com/ujjaval-verma/protocolward.ai\n'      > "$T/docs/n6ok.md"
git -C "$T" add -A

out="$("$here/check-public.sh" "$T" 2>&1)" && { echo "check-public selftest: expected failure on bad tree" >&2; exit 1; }
block() { awk -v l="check-public: $1" 'index($0,l)==1{p=1;next} /^check-public: /{p=0} p' <<<"$out"; }
expect() { # expect "<label>" file...
  local label="$1"; shift
  local b; b="$(block "$label")"
  [[ -n "$b" ]] || { echo "check-public selftest: rule '$label' did not fire" >&2; exit 1; }
  for f in "$@"; do
    grep -q "^$f:" <<<"$b" || { echo "check-public selftest: '$label' did not flag $f" >&2; exit 1; }
  done
}
expect "private or internal-only reference" d.txt
expect "price figure in public copy" docs/a.md docs/q.md site/p.html deploy/p.yaml deploy/p.json h.sh
expect "citation of an unpublished design note" b.go docs/n2a.md notes/n2b.md
expect "citation of an unpublished spec section in Go" f.go g.go
expect "pre-beta module path" i.go docs/n6a.md docs/n6b.md
expect "commit hash that dies with the squash" docs/c.md e.go
for f in testdata/eval/x.jsonl ok.sh docs/n6ok.md; do
  if grep -q "^$f:" <<<"$out"; then echo "check-public selftest: $f wrongly flagged" >&2; exit 1; fi
done

# A subdirectory invocation still scans the whole repo.
"$here/check-public.sh" "$T/sub" >/dev/null 2>&1 && { echo "check-public selftest: subdir run missed repo root" >&2; exit 1; }
# Outside a git work tree: labelled error, non-zero.
N="$(mktemp -d)"
err="$("$here/check-public.sh" "$N" 2>&1)" && { echo "check-public selftest: non-git dir should fail" >&2; rm -rf "$N"; exit 1; }
rm -rf "$N"
grep -q '^check-public: ' <<<"$err" || { echo "check-public selftest: non-git error unlabelled" >&2; exit 1; }

# A repo with nothing tracked (e.g. a fresh `git init` before `git add -A`) must not pass vacuously.
E="$(mktemp -d)"; git -C "$E" init -q; echo x > "$E/f"
err="$("$here/check-public.sh" "$E" 2>&1)" && { echo "check-public selftest: zero tracked files should fail" >&2; rm -rf "$E"; exit 1; }
grep -q '^check-public: no tracked files' <<<"$err" || { echo "check-public selftest: zero-file error unlabelled" >&2; rm -rf "$E"; exit 1; }
rm -rf "$E"

git -C "$T" rm -q -f docs/n6a.md docs/n6b.md docs/n6ok.md docs/n2a.md notes/n2b.md docs/q.md site/p.html deploy/p.yaml deploy/p.json docs/a.md b.go docs/c.md d.txt e.go f.go g.go h.sh i.go
"$here/check-public.sh" "$T" >/dev/null || { echo "check-public selftest: clean tree should pass" >&2; exit 1; }

# A pattern git grep rejects (exit > 1) must fail loudly, not pass as "no hits".
B="$(mktemp)"
sed 's/investor|confidential/investor(|confidential/' "$here/check-public.sh" > "$B"
grep -q 'investor(|confidential' "$B" || { echo "check-public selftest: broken-pattern mutation did not apply" >&2; exit 1; }
err="$(bash "$B" "$T" 2>&1)" && { echo "check-public selftest: invalid pattern should fail" >&2; exit 1; }
grep -q '^check-public: private or internal-only reference: git grep failed' <<<"$err" || { echo "check-public selftest: invalid-pattern error unlabelled" >&2; exit 1; }
echo "check-public selftest: OK"
