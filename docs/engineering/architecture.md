# Architecture

Protocol Ward is a DNS resolver with a three-tier defence, built as one Go binary. This document describes the packages that exist today and those that are planned, the boundaries between them, and the data flow for a query.

## High-level diagram

```
 DNS client ──► internal/dataplane
                  │
                  ├─ decoy hit (internal/decoy; matched before the policy engine) ─► alert + configured block answer; never forwarded
                  │
                  ├─ internal/policy.Decide (allowlist, then blocklists)
                  │     ├─ block ─► configured block answer
                  │     └─ allow / miss ─► forward (internal/upstream, DoT)
                  │
                  └─ after a forward, if a classifier is configured: async classify
                        ├─ built-in pkg/detect (Assessor path) ─► flag only ─► log line + dashboard flags (internal/web)
                        └─ sibling process (internal/model) ─► verdict logged, never applied
```

## Tiers

### Tier 1: Blocklists and allowlists (fast path, in memory)

`internal/hostlist` parses hosts-format sources and compiles them into a reversed-label suffix set. `internal/allowlist` wraps it for allowlist semantics. `internal/policy.Engine.Decide` checks the allowlist (precedence), then blocklists, and returns a typed `Decision`; `internal/dataplane` executes it. Decoys are matched by `internal/dataplane` *before* `Decide` runs, so an allowlist entry can never mask a decoy hit (Tier 3). Lists are whatever the operator configures. A curated, signed default bundle is planned.

### Tier 2: Behavioral detection (async, flag-only in beta)

When the fast path forwards a name, `dataplane.classifyAsync` asks a classifier for a verdict without delaying the answer. The classifier is either the built-in `pkg/detect` lexical detector (`model: {builtin: lexical}`) or a sibling process speaking newline-JSON over stdio through `internal/model`. The detector analyses each hostname that misses your lists today; timing and per-device history are coming soon. It does not score single-label names, local-use TLDs (`lan`, `local`, `home.arpa` and similar), reverse-DNS names or punycode labels. On the built-in path, `ward serve` also skips listed OS connectivity-probe zones (today `msftncsi.com`), which LAN clients poll on their own. Verdicts conform to `pkg/schema` and are **recorded and flagged, never enforced** in the beta. Enforcement is planned.

### Tier 3: Decoys

`internal/decoy` holds tripwire hostnames. `internal/dataplane` matches them before the policy engine runs. A hit is logged as a `policy: alert` line with the decoy ID and answered with the configured block response; the query is never forwarded, so the decoy name never reaches an upstream. No model runs. Decoys are kept out of every export (invariant 6).

## Packages that exist

| Package | Responsibility | Stable API? |
|---|---|---|
| `cmd/ward` | The `ward` binary: `serve`, `doctor`, `config export`, `update verify`, `eval`, `version` | — |
| `cmd/wardwasm` | `GOOS=js GOARCH=wasm` bridge exposing `ward.init/assess/decide/exportConfig` to the browser demos | — |
| `cmd/wardwasm/internal/demo` | Plain-Go, natively tested core of the WebAssembly demo | No |
| `cmd/wardtestmodel` | Deterministic test sibling for the classifier contract | — |
| `cmd/wardtestdot` | Test DNS-over-TLS upstream for the harness | — |
| `internal/dataplane` | DNS server; executes policy decisions; async classify fork | No |
| `internal/policy` | Deterministic, exhaustively cased decider (pure, no I/O) | No |
| `internal/hostlist` | Hosts-format parser and suffix-match set; in-memory constructor for the demo | No |
| `internal/allowlist` | Thin allowlist wrapper over `hostlist` | No |
| `internal/decoy` | Tripwire hostname set and alert attribution | No |
| `internal/config` | YAML loader and validation (no Viper) | No |
| `internal/configexport` | Decoy-free export document shared by the CLI and the WebAssembly demo (no `model:` stanza today) | No |
| `internal/upstream` | Persistent DNS-over-TLS upstream client | No |
| `internal/model` | Sibling-process classifier adapter (spawn, stdio RPC, input sanitising) | No |
| `internal/update` | TUF metadata + cosign signature verification | No |
| `internal/obs` | `slog` JSON logger setup and test log capture | No |
| `internal/web` | Read-only dashboard and `/healthz` | No |
| `pkg/schema` | Typed verdicts, `Assessment`, `Reason` | **Yes, Apache-2.0** |
| `pkg/model` | `Classifier` and optional `Assessor` interfaces | **Yes, Apache-2.0** |
| `pkg/detect` | Lexical hostname detector (pure Go, stdlib only, wasm-safe) | **Yes, Apache-2.0** |

## Planned

| Package | Responsibility |
|---|---|
| `internal/feed` | Client for the signed, pull-only blocklist and model update channel (placeholder directory today) |
| `internal/relay` | Opt-in alert relay carrying alert metadata only (Pro; placeholder directory today) |
| `pkg/proxy` | Reverse-proxy primitives (placeholder directory today) |
| `internal/policy` runtime matcher | Learned blocks from verdicts (enforcement mode) |

## Data flow for one query

1. A query arrives at `internal/dataplane`, which lowercases the name and strips the trailing dot.
2. Decoy match (checked first, in the dataplane): emit `policy: alert` with the decoy ID, answer with the configured block response, never forward.
3. Otherwise the dataplane calls `policy.Engine.Decide(qname)`. Allowlist match: forward upstream and emit `policy: allowed`.
4. Blocklist match: answer with the configured block response and emit `policy: blocked` with list and rule.
5. Otherwise forward upstream over DoT. If a classifier is configured, classify asynchronously; with the built-in detector, a non-benign result is recorded as a dashboard flag with its score and reasons. The answer is never delayed or changed by the verdict in the beta.

## Known limits (public beta)

- **Classification is unbounded.** Every forwarded query spawns one classify goroutine (`dataplane.classifyAsync`), bounded only by the classify timeout and drained on shutdown. There is no worker pool or rate limit, so a query flood means a goroutine flood. The built-in lexical detector runs in-process and is a cheap, pure in-memory computation, which is why this is accepted for the beta.
- **A busy external classifier can switch classification off.** Sibling (`model.command`) classifiers are serialised behind one lock in `internal/model`, and that lock does not honour the classify timeout. In a burst, queued calls wait their turn; a call whose deadline has already passed when it gets the lock marks the adapter unavailable. Ward then logs `policy: model unavailable` and stops classifying until `ward serve` is restarted. Answers are unaffected.
- **No deduplication, short memory.** A name is assessed every time it is forwarded, and a repeat flag is recorded again. The dashboard keeps the 50 most recent flags in memory; they are lost on restart (the log keeps every `policy: classified` line).
- **`ward config export` omits the `model:` stanza.** A round-tripped export runs fast-path only until `model:` is added back. Decoys are unaffected (invariant 6).
- **The connectivity-probe skip lives in `ward serve` only.** `ward eval --builtin` and the WebAssembly demo still score `msftncsi.com` as malicious.

## Why this layout

- The boundaries follow the invariants (`docs/engineering/invariants.md`). Classifiers live behind `pkg/model` so they are swappable. The policy engine lives in `internal/` because its correctness is non-negotiable.
- `pkg/schema` is the contract between classifier output and deterministic Go control flow. A flipped label still has to map to a handler.
- One binary. The only exception is the optional model sibling process, which isolates a local model from the data plane (invariant 3).
