# Spec Review Discipline

The adversarial review that fires **before** any code is written — against the spec and plan together — to catch the class of bug that survives into shipped code and only gets found by the post-code Ralph review.

Sometimes called the "T0 review" because it runs as task T0 of a slice (before the tracer-bullet task T1). The post-code Ralph review at [code-review.md](code-review.md) is its mirror: same disposition format, different surface and different lens.

## Why it exists

The `make-dod-v0.1` slice shipped with two doc lies that survived from spec into code: a config-fixture comment claiming `SSL_CERT_FILE` was set when it wasn't, and a TODO blocker pointing at the wrong remedy. Both were factually inconsistent with the rest of the spec at write-time; the post-code Ralph review caught them, but only after days of cascading code that took them as ground truth. A spec-stage adversarial pass would have caught them in minutes.

In short: **spec-review catches consistency lies before they fossilize into code**. Code-review catches what the spec couldn't have anticipated. Both are needed.

## When the spec review fires

Once per slice, at task T0 — after the spec and plan are drafted, before any production code (or scaffolding) is written. The maintainer runs it on every non-trivial slice; for other contributors it is optional (CLAUDE.md).

T0 spec-review does **not** count against the 8-task slice budget, same exemption as the post-code Ralph review task.

For maintainer slices, skipping T0 is allowed only when explicitly noted in the plan with a reason (e.g. the bootstrap slice that *creates* the spec-review template can't apply it to itself). Skips are documented in the plan, not implicit.

## The subagent prompt (copy into the slice's plan)

Give the prompt below to a fresh reviewer (a subagent such as Claude Code's `general-purpose`, or a human). Paste-template:

```
You are reviewing the SPEC AND PLAN for slice <slice-id> on Protocol Ward,
BEFORE any code is written. Your job is to catch lies, inconsistencies,
and misalignment with the product before they fossilize into code.

Context you must read first:
  - docs/product/vision.md                 — the product thesis
  - docs/product/pitch.md                  — the framing
  - docs/engineering/invariants.md         — non-negotiable rules
  - docs/engineering/architecture.md       — current layering
  - docs/engineering/decisions/             — all ADRs (durable design decisions)
  - docs/engineering/definition-of-done.md — the current-version acceptance contract
  - docs/superpowers/specs/<spec>.md       — the spec under review
  - docs/superpowers/plans/<plan>.md       — the plan under review

Be adversarial. Apply two lenses in order:

LENS A — Factual accuracy / internal consistency:
  1. Does the spec contradict itself? (Same field described two ways,
     same behavior with two different acceptance criteria, etc.)
  2. Does the plan contradict the spec? (A task that delivers something
     the spec doesn't ask for, or skips something the spec requires.)
  3. Does the spec name files, fields, flags, or behaviors that don't
     exist in the current codebase? (Names from a future slice that
     hasn't shipped, or names from a past slice that got renamed.)
  4. Are the "Verification" criteria actually testable, or do they hand-
     wave? (E.g. "behaves correctly" vs. "returns 0.0.0.0 and logs
     policy:blocked with the matched qname".)
  5. Are the "Non-scope" items actually scoped out, or are they smuggled
     back in via a task? (A common drift: spec says "no DB changes" but
     a task adds a migration.)

LENS B — Product / invariant alignment:
  6. Does the spec violate any invariant? (Cite the invariant number.)
  7. Does the spec contradict a shipped ADR? (Cite the ADR number.)
  8. Does the spec assume a value judgment that has multiple internally-
     consistent answers — i.e. does it pick a default that needs explicit
     human sign-off, not a subagent's? Flag these as DEFERRED with a note
     so the operator can confirm.
  9. Does the spec align with the product vision? Is this slice on the
     critical path to the current target version's Definition of Done,
     or is it a tangent?
  10. Does the slice fit the scope budget? (≤8 tasks AND ≤3 production
      Go files in internal/+pkg/.)

Output format: a Markdown report with three sections — BLOCKING, NIT,
DEFERRED — each section a numbered list. For each finding, give: a one-
line subject, the file:line in the spec or plan, which lens caught it
(A or B), why it matters, and a concrete fix.

Empty sections are fine; say "None." rather than omitting the section.

Do not write code or edit files. Report only.
```

Save the subagent's report to `docs/superpowers/reviews/<YYYY-MM-DD>-<slice-id>-spec-ralph.md`. The trailing `-spec-ralph.md` suffix distinguishes it from the post-code `<slice-id>-ralph.md` so both can coexist. The path is under gitignored `docs/superpowers/` and is transient by design; the pruner ([scripts/prune-superpowers.sh](../../scripts/prune-superpowers.sh)) treats `-spec-ralph.md` the same as `-ralph.md` — pruned once the slice ships and the quarantine elapses.

## Disposition format

Every finding gets one of three dispositions. Same shape as code-review.md, with one critical difference: a BLOCKING finding at T0 means **fix the spec/plan, then continue** — not "fix the code, then continue", because there is no code yet. The cost of fixing the spec is small; the cost of unwinding code that implemented a bad spec is large.

| Disposition | Meaning | Outcome |
|---|---|---|
| **BLOCKING** | Spec or plan must be corrected before T1 begins. Invariant violations, ADR contradictions, spec/plan disagreement, named-but-nonexistent surfaces. | Edit the spec or plan in place. Record the disposition in a `## Dispositions` section appended to the spec-ralph review file. No fix commit is needed if the spec/plan was never committed yet (docs/superpowers/ is gitignored). |
| **NIT** | Worth fixing but doesn't block. Phrasing, clarity, missing cross-references. | Optional edit, optional disposition record. |
| **DEFERRED** | Real concern, but the resolution belongs to a future slice OR requires human sign-off the subagent can't give. | Record in the disposition section. If slices are being run by an autonomous agent loop, lens-B DEFERRED findings that flag a needed human judgment call **pause the loop** until the operator confirms or overrides. |

## Interaction with autonomous agent loops

When an agent runs slices autonomously, T0 spec-review is the load-bearing pause point:

- **No BLOCKING findings, no lens-B DEFERRED requiring human sign-off** → proceed to T1.
- **Any BLOCKING finding** → auto-fix the spec/plan if the fix is mechanical (rename, cross-reference, scope-out clarification). Re-run T0 once. If a second BLOCKING surfaces, **stop the loop** and surface to the operator.
- **Lens-B DEFERRED flagging a value judgment** → **stop the loop**, surface to operator, wait for sign-off before proceeding.

This is how an autonomous loop stays autonomous without becoming reckless.

## Relationship to other reviews

- **T0 spec-review** (this doc) — adversarial review of spec + plan, before code. Catches consistency lies and product misalignment.
- **Post-code Ralph review** ([code-review.md](code-review.md)) — adversarial review of the diff, after code. Catches what the spec didn't anticipate.
- **`make ci`** — mechanical correctness (lint, vet, race tests, build).
- **`make dod`** — feature existence at the version-acceptance level.

The four are complementary, not redundant. Skipping any of them is a documented choice, not a default.
