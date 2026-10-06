#!/usr/bin/env bash
# Prune slice-scoped scaffolding under docs/superpowers/ once the slice is
# shipped and a quarantine period has elapsed.
#
# Rule: a file under docs/superpowers/plans/ or docs/superpowers/reviews/ is a
# prune candidate if BOTH:
#   1. its slice-id appears in `git log origin/main` (i.e. the slice shipped), AND
#   2. its mtime is older than 7 days (quarantine for late Ralph fixes / amends).
#
# Specs are NOT pruned by this script — their durable content gets promoted
# to an ADR or folded into a tracked engineering doc per the rubric in
# docs/engineering/code-review.md. Decide spec disposition at slice closeout.
#
# Naming conventions the script depends on:
#   - Plan filenames end in -plan.md
#   - Review filenames end in -ralph.md (post-code Ralph) or -spec-ralph.md
#     (T0 spec-review; see docs/engineering/spec-review.md)
#   - Spec filenames end in -design.md (informational; specs aren't pruned)
#   - The <slice-id> segment between the YYYY-MM-DD- prefix and the trailing
#     -plan/-ralph/-design suffix MUST match the slice-id token used in the
#     slice's commit messages, e.g. `feat(scope): T1 ... (<slice-id> T1)`.
#
# Known limitation: plan files predating the slice-id-in-commit-scope
# convention (currently 3 such files on disk) will never auto-prune because
# their slice-ids never appear in `git log`. Delete those manually at
# operator discretion.
#
# Dry-run by default; pass --apply to actually delete.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
apply=0
quarantine_days=7

for arg in "$@"; do
  case "$arg" in
    --apply) apply=1 ;;
    --days=*) quarantine_days="${arg#--days=}" ;;
    -h|--help)
      cat <<EOF
usage: prune-superpowers.sh [--apply] [--days=N]

Prints prune candidates under docs/superpowers/{plans,reviews}/. With --apply,
deletes them. Default quarantine is 7 days since file mtime. --days=0 means
"no quarantine" (any age eligible) — useful for slice closeout on same-day.
EOF
      exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

if ! [[ "$quarantine_days" =~ ^[0-9]+$ ]]; then
  echo "prune-superpowers: --days must be a non-negative integer, got '$quarantine_days'" >&2
  exit 2
fi

cd "$repo_root"

# Pull the commit log once. We grep filenames against it.
log="$(git log origin/main --format=%B 2>/dev/null || true)"
if [[ -z "$log" ]]; then
  echo "prune-superpowers: no origin/main commits readable; nothing to prune" >&2
  exit 0
fi

candidates=()
for dir in docs/superpowers/plans docs/superpowers/reviews; do
  [[ -d "$dir" ]] || continue
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    # Derive slice-id: strip the leading YYYY-MM-DD- and the trailing
    # -plan.md / -ralph.md / -design.md / -plan-foo.md suffix.
    base="$(basename "$f" .md)"
    # Strip YYYY-MM-DD- prefix
    stripped="${base#????-??-??-}"
    # Strip trailing -plan, -ralph, -spec-ralph, -design (with any further suffixes)
    slice_id="$(echo "$stripped" | sed -E 's/-(plan|spec-ralph|ralph|design)([-.].*)?$//')"
    if [[ -z "$slice_id" || "$slice_id" == "$stripped" ]]; then
      # Filename didn't match the expected shape; skip silently.
      continue
    fi
    if grep -qF "$slice_id" <<<"$log"; then
      candidates+=("$f")
    fi
  done < <(
    if (( quarantine_days == 0 )); then
      find "$dir" -type f -name '*.md' 2>/dev/null
    else
      find "$dir" -type f -name '*.md' -mtime +"$quarantine_days" 2>/dev/null
    fi
  )
done

if (( ${#candidates[@]} == 0 )); then
  echo "prune-superpowers: nothing to prune (quarantine=${quarantine_days}d)"
  exit 0
fi

echo "prune-superpowers: ${#candidates[@]} candidate(s) under docs/superpowers/:"
for f in "${candidates[@]}"; do
  echo "  $f"
done

if (( apply == 0 )); then
  echo ""
  echo "Dry-run. Re-run with --apply to delete."
  exit 0
fi

for f in "${candidates[@]}"; do
  rm -- "$f"
  echo "deleted: $f"
done
