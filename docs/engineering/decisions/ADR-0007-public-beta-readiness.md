# ADR-0007 — Public Beta Readiness

- **Status:** Accepted
- **Date:** 2026-10-05
- **Author:** Ujjaval Verma
- **Supersedes:** ADR-0001 D6 (licence split)
- **Amends:** ADR-0001 (D7, D13), ADR-0002 (§1, text amended in place)
- **Related:** ADR-0006 (hybrid classifier direction)
- **Amended:** 2026-10-06 — the rig run gates GA (non-prerelease) tags only; beta tags are gated by `make ci`, `make dod` and `make audit` (operator decision; see `release.md`). Publishing completed 2026-10-06; the squashed-tree gate run and the pre-launch operator action were one-time launch steps.

## Context

Protocol Ward is going public as a beta. The public repository starts from one squashed commit of this tree, and its Go module path is `protocolward.ai/ward`. A docs site at protocolward.ai, kept in a separate repository, serves the module's `go-import` meta tag and two in-browser demos. Several things in the private tree were written for a solo, private phase: fundraising decks, a holding page, prices, citations of unpublished design notes, and agent guidance that assumes the maintainer's personal tooling. This ADR records what changed for the public tree and why, so that a fresh clone explains itself.

## Decision

1. **Fundraising decks leave the repository.** The HTML/PDF decks under `docs/product/` move to the docs-site repository's private, never-deployed archive. Anti-goal 20 in `invariants.md` existed only to protect one of those decks, so it is deleted. `docs/product/pitch.md` stays, fact-checked.
2. **The landing site lives outside this repository.** The holding page under `site/` is deleted. ADR-0001 D13's `/site` directory is superseded by the separate docs-site repository.
3. **Visibility is not gated on the rig run.** ADR-0001 D7 said the repo flips public after MVP+ v0.1 runs end to end on the Mac mini rig. For the public beta, "beta" is a label with no gate. The rig checklist in `release.md` now gates **tagged releases**, not repository visibility.
4. **No prices in public docs.** Tier names stay; price figures are removed from `deployment-modes.md` and ADR-0001 D1.
5. **Unpublished design notes are cited as such.** ADRs and code comments that pointed at dated files in the gitignored design-notes directory now say "internal design notes (not published)". Commit hashes that the squash would orphan are replaced by slice names. As an editorial exception to ADR-0006 D4 ("existing accepted ADRs are not rewritten"), ADR-0003's SP10b row label and the Definition of Done wording adopt ADR-0006's "reference sibling adapter" term, and the Definition of Done v0.1 scope sentence is corrected to what shipped (operator-configured blocklists; "reverse proxy" dropped); no decision changes.
6. **Apache-2.0 everywhere (operator decision, 2026-10-05; supersedes ADR-0001 D6).** ADR-0001 D6 licensed the core under AGPLv3 and `pkg/` + `plugins/` under Apache 2.0, with an Enterprise tier sold as a commercial licence of the same code. The whole repository (root, `cmd/`, `internal/`, `pkg/`, `plugins/`, `scripts/`) is now licensed under the Apache License 2.0. The maintainer is the sole copyright holder, so this is a decision, not a negotiation. Rationale:
   - **Adoption.** Router OEMs, homelab distributions and integrators can embed and ship Ward without copyleft review; the AGPL network clause was a blocker for exactly the deployments a DNS appliance needs.
   - **Explicit patent grant.** Apache-2.0 §3 grants a patent licence from every contributor, with defensive termination for anyone who sues, so moving to a permissive licence does not cost users the patent protection AGPLv3 §11 gave them (MIT or BSD would have).
   - **Monetisation does not rest on the code licence.** Pro is managed signed feeds, the opt-in alert relay and support: services that no code licence protects either way. Enterprise is **commercial add-ons, support and managed services**, not a commercial licence of the core.
   - **Trade-off accepted.** A permissive release is irreversible for every published version, and there is no dual-licensing revenue. A competitor may host or fork Ward without sharing changes.

   Mechanics: one root `LICENSE` with the canonical Apache-2.0 text (the per-directory `pkg/LICENSE` and `plugins/LICENSE` are removed as redundant), and a root `NOTICE` (Apache-2.0 §4(d)) with the copyright line and the third-party data attributions. Every Go file starts with `// SPDX-License-Identifier: Apache-2.0`; `scripts/check-spdx.sh` enforces it in `make check`.
7. **Contributions use the DCO; no CLA.** Contributions are licensed under Apache-2.0, the same licence as the project (inbound = outbound), and each commit carries a DCO sign-off. Because there is no dual-licensing, no Contributor License Agreement is needed.
8. **A leak gate.** `scripts/check-public.sh` fails on private names, price figures, citations of dated design notes, orphaned commit hashes and the pre-beta module path. It runs in `make check` and on the squashed tree before publishing.
9. **Invariant clarifications.** Invariant 3 states that the classical in-process detector (ADR-0006) is not a model runtime, so it is not an exception to "one binary". Invariant 4 now defines *flow data* (forwarding to the operator-configured upstream resolver is the DNS service, not an export) and *alert metadata* (event type, list or rule identifier, timestamp, device label; the only hostname is an operator-planted decoy name). Invariant 6 names its tests without a stale slice reference. Invariant 7 records that the one-click override is not built yet (the commitment is unchanged). Anti-goal 16 records v0.1 as shipped history.
10. **CI stays deferred.** No PR CI at the public beta. ADR-0002 is amended in place (2026-10-05) rather than superseded.

## Consequences

- A fresh clone of the public repository carries no private material, and `make check` keeps it that way.
- The README, pitch and vision describe only what ships. Unbuilt features are labelled "coming soon" or "planned".
- Anyone may use, modify, embed and redistribute Ward, including commercially and as a hosted service, under Apache-2.0. Revenue comes from Pro services and Enterprise add-ons, support and managed services, not from licensing the core.
- Earlier private revisions were AGPLv3-licensed by the same sole copyright holder; the public repository starts from a squashed commit and carries Apache-2.0 only.
- **Operator action before publishing (pre-L3):** confirm IP ownership of every commit in the tree, in particular code authored while using third-party work email identities (employer or client accounts). Rewrite the author on the squashed commit to the maintainer's public address only after ownership is confirmed; if any code is not clearly owned, remove or rewrite it before the public commit.

## Revisit conditions

- A paid add-on needs code that cannot be Apache-2.0: it ships as a separate, separately licensed module outside this repository, by a new ADR. The core stays Apache-2.0.
- Outside pull-request volume outgrows local review: revisit ADR-0002 and add PR CI.
