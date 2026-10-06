# ADR-0001 — Foundation Design

- **Status:** Accepted
- **Date:** 2026-05-21
- **Author:** Ujjaval Verma
- **Amended by:** ADR-0007 (D6 licence split superseded: Apache-2.0 everywhere; D7 visibility gate; D13 site location; pricing figure and unpublished-note citations removed 2026-10-05)
- **Spec:** internal design notes (not published); this ADR is the durable summary

## Context

Before any implementation begins, Protocol Ward needs alignment on repository topology, deployment tiers, MVP+ slice scope, dev tooling taste, surface inventory, and the path from private development to public launch. Without this, every sub-project risks contradicting another or solving problems out of order.

## Decision

Thirteen calls, summarized here. The per-decision rationale lives in internal design notes that are not published; this ADR records the decisions.

| # | Decision |
|---|---|
| D1 | **Pro tier = managed signed feeds + opt-in cloud alert relay.** Alert metadata only; no flow data egress. Priced near cost. |
| D2 | **MVP+ v0.1 = decoys + blocklists + CLI + read-only web dashboard. No AI in v0.1.** Gemma slow-path lands in v0.2. |
| D3 | **Per-device roadmap.** v0.3 = WireGuard Roaming Mode (Pro feature, paid trial), Headscale-compatible. Phase 2 = SwiftUI + Network Extension native macOS client (premium Pro). No Electron. |
| D4 | **Pro+ Mesh is a candidate future tier**, not a commitment. Added to vision.md as Bet 5 with break-conditions. Architect Roaming to keep the mesh door open. |
| D5 | **Single Go-rooted monorepo.** Layout: `/cmd`, `/internal`, `/pkg`, `/plugins`, `/web`, `/site`, `/docs`, `/deploy`. |
| D6 | **License split.** AGPLv3 at root; Apache 2.0 in `/pkg` and `/plugins`. Enterprise tier (Phase 3) on commercial license against the same codebase (Grafana pattern, **not** SSPL). **Superseded by ADR-0007 (2026-10-05): Apache-2.0 everywhere; Enterprise is commercial add-ons, support and managed services.** |
| D7 | **Repo flips public when MVP+ v0.1 runs end-to-end on the Mac mini rig.** Not at first commit. Not at v1.0. **Amended by ADR-0007 (2026-10-05): the rig run gates tagged releases, not repository visibility.** |
| D8 | **Test rig: Mac mini M4 Pro (24 GB), ethernet to router, DNS-forwarder mode.** Router DHCP DNS points to the mini. Decoys hosted on the mini under LAN-resolvable hostnames. |
| D9 | **Docs taxonomy.** DESIGN.md at root = brand DNA. `docs/superpowers/` is gitignored (brainstorm drafts); crystallized decisions are promoted to ADRs in `docs/engineering/decisions/`. |
| D10 | **Dev tooling: stdlib-first, battle-tested over novel.** miekg/dns, stdlib reverse-proxy, cobra (no Viper), lipgloss, slog, modernc.org/sqlite, sigstore/cosign + TUF, goreleaser, golangci-lint. Web: React + Vite + Tailwind + shadcn. Landing: Astro. |
| D11 | **Visual identity = slate + warm amber + muted teal.** Security-operations register. Distinct from sassygit/peerdb purple-gradient SaaS register. |
| D12 | **CLI = single `ward` binary.** Cobra subcommands; `ward doctor` is the taste flagship. Dashboard default port `18987` (configurable). |
| D13 | **Landing site `/site` is a parallel track on Astro.** Holding page at protocolward.ai immediately; full landing ships with MVP+ public launch. |

## Consequences

- The repo can start scaffolding immediately (this sub-project) without ambiguity.
- Phase 1 has no cloud infrastructure dependency; Pro infra (alert relay, license signing, Stripe) lands only with v0.3.
- Decisions D2 and D7 together commit us to a discrete public-launch event, not a continuous public history.
- D11's visual register direction means we will not borrow from any of: Cloudflare orange, sassygit purple, Linear ramp gradients, or the cyan-cybersecurity cliché. Every UI surface respects this.

## Revisit conditions

This ADR is reopened if any of the following hold:

- A locked decision (D1–D13) is found to be technically infeasible at implementation time. Open a new ADR superseding the specific decision; do not edit history.
- Bet 1, 2, 3, or 4 in vision.md trips a break condition.
- A new tier (e.g., government / sovereign-cloud SKU) requires reshaping the license split.

## References

- `docs/product/vision.md` — full product thesis with Bets 1–4
- `docs/product/pitch.md` — supply-chain attack framing
- `docs/product/deployment-modes.md` — operational summary of tiers
