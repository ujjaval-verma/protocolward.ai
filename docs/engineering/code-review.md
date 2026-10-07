# Code Review Discipline

This document defines two things:

1. **The adversarial review** that every non-trivial slice runs before push. Sometimes called the "Ralph" review after the maintainer's workflow that introduced it.
2. **The spec-promotion rubric** that decides whether a shipped slice's design doc becomes a tracked ADR or is deleted.

Both exist so that future Claude sessions and future human contributors run the same review in the same shape — instead of re-deriving the prompt and the disposition format every slice.

## When the adversarial review fires

Once per slice, after all functional tasks are green and before push. The maintainer runs it on every slice that touches `internal/` or `pkg/`; for other contributors it is optional (CLAUDE.md). Optional but recommended for docs-only or scripts-only slices that introduce new authored content (a doc the next contributor will read as ground truth deserves an adversarial pass — docs drift silently in a way code does not).

A second review may fire mid-slice as a checkpoint when a task is unusually risky (e.g. the first commit that introduces a new wire-format or a panic-recovery path). Checkpoint reviews are scoped to the single task; the end-of-slice review is scoped to the whole diff.

## The subagent prompt (copy into the slice's plan)

Give the prompt below to a fresh reviewer (a subagent such as Claude Code's `general-purpose`, or a human). Paste-template:

```
You are reviewing slice <slice-id> on Protocol Ward (main branch).

Context you must read first:
  - docs/engineering/invariants.md         — non-negotiable rules
  - docs/engineering/architecture.md       — current layering
  - docs/engineering/testing.md            — per-surface test discipline
  - docs/superpowers/specs/<spec>.md       — the design this slice executes
  - docs/superpowers/plans/<plan>.md       — the task list this slice executes
  - git diff origin/main..HEAD             — the change under review

Be adversarial. Your job is to find what's wrong, not to validate. Specifically:

  1. Invariants violated. Any rule in invariants.md broken? Cite the rule number.
  2. Spec drift. Does the diff diverge from the spec? Either fix the diff or
     update the spec; don't let them disagree silently.
  3. Test gaps. Does any new behavior lack a test that would catch its regression?
  4. Silent failures. Any swallowed error, ignored ctx.Err(), bind that can fail
     without surfacing, log line missing attribution?
  5. Honesty gates. Any fake-live behavior, mocked path presented as real, log
     line containing raw user input or other sensitive data?
  6. Public-surface bloat. New exported symbol that should be unexported, or
     interface that's wider than its sole caller needs?
  7. Documentation lies. Any comment or doc that no longer matches the code,
     or names a thing that doesn't exist?

Output format: a Markdown report with three sections — BLOCKING, NIT, DEFERRED
— each section a numbered list. For each finding, give: a one-line subject, the
file:line, why it matters, and a concrete fix. Empty sections are fine; say
"None." rather than omitting the section.

Do not write code or edit files. Report only.
```

Save the subagent's report to `docs/superpowers/reviews/<YYYY-MM-DD>-<slice-id>-ralph.md`. That path is gitignored under `docs/superpowers/`; the report is transient by design and gets pruned (see [scripts/prune-superpowers.sh](../../scripts/prune-superpowers.sh), `make prune-superpowers`).

## Disposition format

Every finding gets one of three dispositions, recorded either in a follow-up commit body or appended to the review doc:

| Disposition | Meaning | Commit convention |
|---|---|---|
| **BLOCKING** | Must be fixed before push. Invariant violations, missing tests for shipped behavior, silent failures. | `fix(<scope>): T<n> Ralph F<m> — <subject> (<slice-id> T<n>)` |
| **NIT** | Should be fixed but won't block. Naming, comment polish, minor extraction. | Same prefix, or fold into an unrelated commit if trivial. |
| **DEFERRED** | Real finding, but the fix belongs to a future slice. Record in the commit body of the next functional commit, AND open a tracker entry (Markdown TODO in the slice's plan, ADR if architectural). | No fix commit. The decision-to-defer is itself an artifact. |

`F<m>` is the finding's number in the BLOCKING section (e.g. `Ralph F1`, `Ralph F2`). Numbering resets per review.

A slice cannot ship until every BLOCKING finding has a corresponding fix commit. The commit trail is the audit trail; reviewers (human or machine) should be able to grep `git log --grep='Ralph F'` and see every blocking finding accounted for.

## Spec-promotion rubric

When a slice ships, its spec at `docs/superpowers/specs/<YYYY-MM-DD>-<slice>-design.md` is at a fork:

1. **Promote to ADR** if the spec made a decision that future contributors will need to *unwind* to change. Examples: a wire format, a public Go API shape, a security posture, a tier boundary, an explicit anti-goal. Output: a new file under `docs/engineering/decisions/ADR-NNNN-<slug>.md` distilled from the spec — decision + alternatives + consequences, not the full brainstorm. The original spec stays in `docs/superpowers/specs/` as the brainstorm transcript and is eligible for pruning.
2. **Promote into an existing tracked doc** if the spec's durable content is too small for its own ADR but matters for orientation. Examples: a new section in `architecture.md`, a new row in `testing.md`, a new invariant in `invariants.md`. Output: the edit, in the same commit as the slice's final task.
3. **Delete (or let it age out)** if the spec was pure scaffolding — laying out a plan that the commit history now records faithfully. Examples: a refactor with no new public surface, a bug fix with no architectural ripple. Output: nothing tracked. Note: `prune-superpowers.sh` does **not** delete specs (only `plans/` and `reviews/`). Specs require an explicit human disposition call because the promote-vs-delete decision is judgment, not pattern-matching — delete the spec manually at slice closeout, or leave it under `docs/superpowers/specs/` to be pruned on a later manual sweep.

Decide which class the spec belongs to at slice closeout, before running the pruner. If unsure, default to class 2 (promote into an existing tracked doc) — it preserves the durable insight without inventing a new ADR.

Plans (`docs/superpowers/plans/`) and reviews (`docs/superpowers/reviews/`) are always class 3. They are execution scaffolding; the commit history and the disposition trail are the records of truth.

## Relationship to other reviews

This doc covers the **post-code** adversarial pass, run before push. Its sibling [spec-review.md](spec-review.md) covers the **pre-code** adversarial pass at task T0, run before any code is written. Both use the same BLOCKING / NIT / DEFERRED disposition format; the difference is timing and surface — T0 reviews the spec + plan, end-of-slice Ralph reviews the diff. Skipping either is a documented choice, not a default.
