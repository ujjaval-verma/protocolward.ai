# Engineering Invariants

> **Non-negotiable.** A change that violates one of these is a bug, regardless of test coverage.

## Architecture invariants

1. **The AI is a classifier, never a decider.** Slow-path model output conforms to `pkg/schema` and maps to a hardcoded handler in `internal/policy`. The model never has direct effect on connection state.
2. **The policy state engine is deterministic and exhaustively cased.** Every value in the decision enum maps to exactly one handler. Adding a new enum variant without a handler is a compile error.
3. **One binary.** `cmd/ward` produces a single executable. No microservices. The daemon, dashboard and CLI ship in one binary, and the planned update client will too. (The local model runtime in v0.2+ is a sibling process for prompt-injection isolation — that is the only documented exception. The classical lexical detector of ADR-0006, `pkg/detect`, is not a model runtime: it is pure Go with no prompt surface and runs in-process.)

## Data invariants

4. **No flow data leaves the device. Ever.** At any tier. *Flow data* is any record of which names devices looked up or connected to, and when (query, hostname, answer, payload or timing). Forwarding a query to the operator-configured upstream resolver is the DNS service itself, not an export of flow data; no other path may carry flow data off the device: no telemetry, no cloud analysis, no aggregation. The only thing an opt-in alert relay (Pro; planned, not built) may carry is **alert metadata**: event type, the identifier of the list or rule that matched (a list name or rule category, never a hostname), timestamp and an operator-assigned device label. The only hostname that may appear is a decoy name the operator planted. Pro+ Mesh (candidate) follows the same rule.
5. **The update channel is pull-only.** Device initiates connections; no inbound connections are accepted on the update path. Updates are signed (cosign) and verified against TUF metadata.
6. **Decoys do not leak through config exports.** A config dumped from an instance with decoys configured MUST NOT include decoy hostnames in exportable / shareable artifacts. Tested end to end in `internal/decoy/export_test.go`, structurally in `internal/configexport` (the export document has no decoy field), and, for the WebAssembly demo's `exportConfig()`, in `cmd/wardwasm/internal/demo`.

## UX invariants

7. **No silent drops by default.** Every block carries user-visible attribution (which rule, which list, when) and a one-click allowlist override. Status (public beta): attribution ships in the logs and dashboard; the one-click override arrives with an interactive dashboard, and until then the override is an allowlist entry (ADR-0007).
8. **Every error names a remediation.** Logs and dashboard surfaces tell the operator what to do next, not just what went wrong.

## Code-level invariants

9. **`internal/` is not importable.** Go enforces this. Anything that needs to be reused from outside the binary lives in `pkg/`.
10. **`pkg/` has no `internal/` imports.** The public Go API is self-contained.
11. **No third-party config-binding magic.** No Viper. Configuration is plain YAML decoded into Go structs in `internal/config` with explicit validation.
12. **CLI subcommands are pure.** Each `ward <verb>` subcommand reads config, performs the action, and returns. State lives in the daemon, not the CLI; the CLI calls the daemon over its local control socket once `ward serve` exists.

## Anti-goals

Things we are choosing *not* to do, to keep scope honest. An anti-goal is the same shape as an invariant: a change that contradicts one is a bug regardless of test coverage. Promoted from the foundation brainstorm (2026-05-21 UTC) so they survive on a fresh clone.

13. **No consumer hardware SKU.** Per VISION.md Bet 2. We ship software that runs on commodity hardware (Mac mini, RPi-class, x86 NUC).
14. **No Electron.** Anywhere. Native (SwiftUI + Network Extension on macOS, Phase 2) or web-served-from-daemon only.
15. **No Viper.** Plain YAML decoded into Go structs in `internal/config` with explicit validation. (Restates invariant 11 — listed here so the anti-goal is discoverable from either direction.)
16. **No slow-path model in v0.1.** v0.1 shipped fast path + blocklists + decoys + CLI + dashboard. The classifier contract landed in v0.2; the on-device detector direction is ADR-0006.
17. **No Tailscale-equivalent coordination plane built from scratch.** Roaming Mode (v0.3) is Headscale-or-partner; we do not write our own key/coordination protocol.
18. **No TOML + YAML config matrix.** YAML only. One format, one parser, one schema.
19. **No cloud aggregation of flow data, at any tier.** Restates data invariant 4 in absolute terms; listed here so the anti-goal is discoverable when scoping any new feed/relay/telemetry surface.

## How to add a new invariant

Open a PR that updates this document and adds an ADR under `docs/engineering/decisions/` explaining the motivation. Invariants are deletable, but only via the same path that adds them. The same path applies to anti-goals.
