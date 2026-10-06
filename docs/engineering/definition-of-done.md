# Definition of Done

The versioned acceptance contract for Protocol Ward. `make dod` exits 0 only when every bullet below is PASS. TODO bullets exit non-zero so the gate cannot accidentally green-light a partially-built version.

## Current target: v0.2 (Slow-Path)

Scope per `docs/engineering/decisions/ADR-0001-foundation-design.md` D2: slow-path classifier contract (reference sibling adapter) + `pkg/model` / `pkg/schema` model abstraction + eval suite, with v0.1's fast-path DNS + operator-configured blocklists + decoys + `ward` CLI + read-only web dashboard + signed update channel preserved unchanged. **The AI is a classifier, never a decider** (invariant 1) and **the local model runtime is a sibling process** (invariant 3) — both are structurally verified by v0.2 bullets, not merely asserted.

The script that runs these bullets is [`scripts/dod.sh`](../../scripts/dod.sh). The harness is fixture-based; no real network is contacted. The Mac mini rig run (ADR-0001 D7 as amended by ADR-0007) is a separate manual gate for tagged releases — see [`docs/engineering/release.md`](release.md).

### Bullets

| # | Assertion | Source | Status |
|---|---|---|---|
| 1 | `make ci` passes (lint + vet + race tests + build + testing-doc) | universal preflight | PASS |
| 2 | `make audit` passes (`go mod verify` + govulncheck) | universal preflight | PASS |
| 3 | `ward serve --config testdata/dod/ward.yaml` binds 127.0.0.1:5354 within 5s; emits `policy: engine ready` | sub-project 2 + 5 | PASS |
| 4 | DNS: blocked hostname returns the configured block_response AND emits `policy: blocked` log line with matched qname (invariant 7) | sub-project 2 | PASS |
| 5 | DNS: forwarded hostname returns the upstream answer | sub-project 2 | PASS |
| 6 | POLICY: a hostname in both blocklist and allowlist emits `policy: allowed` (not `policy: blocked`) — allow-beats-block precedence | sub-project 3 | PASS |
| 7 | DECOY: a tripwire hostname fires an alert through the policy engine | sub-project 4 (decoy layer) | PASS |
| 8 | DASHBOARD: `GET /healthz` returns 200 with last-decision summary | sub-project 6 (web dashboard) | PASS |
| 9 | EXPORT: `ward config export` does NOT contain any decoy hostnames (invariant 6) | sub-project 4 | PASS |
| 10 | UPDATE: `ward update verify <fixture>` validates a cosign-signed TUF metadata fixture | sub-project 8 (signed update channel) | PASS |
| 11 | CLI: `ward doctor` reports bind-probe + upstream-reachability | sub-project 5 (ward doctor) | PASS |
| 12 | MODEL ABSTRACTION: a `pkg/model.Classifier` returns a typed `pkg/schema.Verdict`; `internal/policy.Engine` consumes the Verdict and yields the expected `Action`. The classifier MUST NOT have any path that touches connection state directly (invariant 1) | ADR-0003 SP10a (model contracts) | PASS |
| 13 | SLOW-PATH: `ward serve` loads the reference sibling adapter; a probe qname triggers async slow-path classification; the resulting Verdict flows through `internal/policy` and produces the expected `policy:` log line | ADR-0003 SP10c (slow-path integration) | PASS |
| 14 | MODEL ISOLATION: the reference sibling adapter runs as a sibling process (invariant 3 exception); `ward serve` continues responding to DNS after the model sibling is SIGKILL'd and either restarts the sibling OR falls back to fast-path-only with a `policy: model unavailable` log line (invariant 7) | ADR-0003 SP10b + SP10c (model isolation; per invariants 3 + 7) | PASS |
| 15 | EVAL: `ward eval --suite testdata/eval/v0.2.jsonl` scores the live classifier against a labelled fixture set; exits non-zero if accuracy drops below a pinned threshold (threshold 0.85 — pinned at SP10d T0) | ADR-0003 SP10d (adversarial-eval suite) | PASS |
| 16 | SHIP: `git log origin/main..HEAD` is empty (slice-closeout sweep) | shipped-means-pushed | SKIP unless `make dod CLOSEOUT=1` |

All 15 functional bullets PASS at SP10d ship; bullet 16 (SHIP) requires `make dod CLOSEOUT=1` and a clean `git log origin/main..HEAD`, then 16 of 16 PASS. Each `make dod` run prints the live count.

## How to use it

- **During development of a sub-project:** ignore the bullets for *other* sub-projects (they stay TODO). Focus on turning your sub-project's bullet from TODO to PASS. The slice that lands the feature also turns its bullet green in `scripts/dod.sh`, in the same commit.
- **At slice closeout:** `make dod CLOSEOUT=1`. The harness adds bullet 16 (no unpushed commits) to the gate.
- **At version readiness:** all PASS, no TODO, no FAIL. That is what "v0.2 done" means — nothing else.

## How a bullet moves from TODO to PASS

1. Find the bullet's `bullet_N_*` function in `scripts/dod.sh`.
2. Replace the `record TODO` body with the real assertion.
3. Update this doc's status column in the same commit.
4. Run `make dod` locally — the new bullet should be PASS.
5. Push; the pre-push hook runs `make ci` (which doesn't include `make dod`, by design — dod is a separate, opt-in gate).

## Rewrite-per-version contract

When v0.2 is shipped (all bullets PASS), the next slice does the v0.3 bump:

1. Rewrite the bullet table in this doc to the v0.3 acceptance set (WireGuard Roaming Mode, Headscale-compatible coordination plane — per the ADR-0001 D3 progression).
2. Rewrite `scripts/dod.sh`'s bullets to match. Previously-PASS bullets that remain v0.3 acceptance criteria stay green; bullets that don't survive the version bump are removed; new bullets land as TODO.
3. Commit as `chore(dod): bump to v0.3 acceptance`.

The git history is the record of what the goal post was at each version. **Do not preserve old versions as `definition-of-done-v0.2.md`** — git is the version store, not the filesystem.

## What `make dod` is NOT

- **Not in `make ci`.** CI is the per-change gate (fast, runs on every commit). DOD is the per-version gate (slow, run intentionally before claiming a release).
- **Not the rig run.** `make dod` is the automated harness. The Mac mini rig run is a separate, manual checklist in `docs/engineering/release.md`. Sub-project 9 (public flip) requires *both* green.
- **Not a substitute for the per-surface testing scope** in `docs/engineering/testing.md`. DOD asserts that the *feature* exists end-to-end; testing.md asserts that the *internals* are tested at the right discipline.
