# ADR-0004 — Classifier Contract

- **Status:** Accepted
- **Date:** 2026-05-26
- **Author:** Ujjaval Verma
- **Spec:** SP10a design notes (internal, not published); this ADR is the durable summary
- **Amends:** ADR-0003 SP10a (Model contracts) — no scope change; this ADR captures the interface decisions reached during SP10a slice 2 that future contributors would need to *unwind* to change.
- **Amended by:** ADR-0006 (2026-10-05) — adds `schema.Assessment` and the optional `model.Assessor`; the classical on-device detector (`pkg/detect`) is the primary classifier and the sibling adapter becomes the "reference sibling adapter" for an optional LLM explainer.

## Context

ADR-0003 decomposed v0.2 into SP10a–d but did not enumerate the public-API shape of the model contract — that was deferred to the SP10a slices themselves. SP10a slice 1 landed `pkg/schema.Verdict`; SP10a slice 2 landed `pkg/model.Classifier`, `pkg/model.Input`, and `internal/policy.Engine.DecideWithVerdict`. Four design calls in slice 2 are load-bearing for SP10b's adapter and SP10c's dataplane fork; they need a durable home outside the gitignored spec.

The SP10a design notes (internal, not published) carry the alternatives-considered context per call. This ADR captures the decisions themselves so a contributor opening SP10b without the gitignored brainstorm draft still sees the contract.

## Decision

### D1 — `pkg/model.Classifier` is a one-method interface returning a typed `schema.Verdict`

```go
type Classifier interface {
    Classify(ctx context.Context, in Input) (schema.Verdict, error)
}
```

The wire-form `pkg/schema.Verdict` enum and the call-contract `pkg/model.Classifier` interface ship in separate packages. Splitting them keeps the wire form independent of the invocation API, so an out-of-tree adapter can target `Classifier` without depending on the policy engine. Per ADR-0001 D6, `pkg/model` is Apache-2.0 stable public API — adding a field to `Input` is non-breaking; renaming or removing a field is. The `Classifier` signature is the load-bearing surface.

### D2 — `Input` is a typed struct, not `[]byte` or a bare hostname

```go
type Input struct {
    Hostname    string   // pre-normalized: lowercase, no trailing dot
    ClientHints []string // attacker-influenced — callers MUST sanitize + length-bound
    UserAgent   string   // attacker-controlled — callers MUST sanitize + length-bound
}
```

Schema-bounded at the API boundary (vision.md Key Risk #6); SP10b's prompt template derives deterministically from typed fields; the field set is additively growable without breaking the stable surface. Token bounding (4–8k per architecture.md Tier 2) is the caller's responsibility — SP10b adapter or SP10c dataplane fork bounds the field values before constructing `Input`. The `pkg/model` package does not enforce bounds.

### D3 — Verdict → Action mapping, including the precedence rule

`internal/policy.Engine.DecideWithVerdict(qname, v)` consults matchers in the order `allow > blocklist > model-verdict > forward`. The model verdict maps:

| Verdict | Action | Kind | MatchedLabel |
|---|---|---|---|
| `VerdictBenign` | `ActionForward` | `KindNone` | `""` |
| `VerdictTelemetry` | `ActionBlock` | `KindBlock` | `"(model)"` |
| `VerdictMalicious` | `ActionBlock` | `KindBlock` | `"(model)"` |

`VerdictBenign` is a first-class decision (the model actively cleared the destination after the lists missed), not a fallthrough. Telemetry and Malicious collapse to the same `Decision` in this layer — the dataplane behavioural split (Telemetry blocks the DNS response only; Malicious additionally severs the connection) lives in SP10c, which threads the `Verdict` alongside the `Decision` rather than packing it into `Decision.Kind`.

Allow and blocklist are re-consulted (not assumed pre-cleared by the caller) so the precedence rule remains a property of the policy engine, not the dataplane caller. Empty qname falls through to the Verdict switch (Benign+empty forwards; Telemetry/Malicious+empty blocks) — the divergence from `Decide`'s empty-qname guard is deliberate: the classifier's verdict is actionable even when the flow has no resolved hostname.

### D4 — `MatchedLabel = "(model)"` is the sentinel for model-sourced blocks

The sentinel cannot collide with real hostnames (`hostnameRE` in `internal/hostlist/parser.go`, `^[a-z0-9.-]+$`, rejects `(`). Reusing `KindBlock` avoids `kind_string.go` regen and exhaustive-switch ripple in v0.2. SP10c MAY introduce `KindModelTelemetry` / `KindModelMalicious` variants if observability needs to switch on them.

## Consequences

- **SP10b** implements `pkg/model.Classifier` inside `internal/` (sibling-process adapter). The Apache-2.0 surface is locked; field additions are allowed, field renames/removals are not.
- **SP10c** wires the dataplane fork against `Engine.DecideWithVerdict`. The Telemetry-vs-Malicious behavioural split is SP10c's responsibility — SP10c MUST thread `Verdict` alongside the returned `Decision` (carry-forward D1 from the SP10a T0 review).
- **`pkg/model` has no upward dependencies.** Imports `context` + `pkg/schema` only. `scripts/dod.sh` bullet 12 Part A grep-asserts the import boundary at every `make dod` run.
- **Token bounding moves to the adapter.** SP10b's slice MUST enforce length/charset sanitization on `Input.ClientHints` and `Input.UserAgent` before any prompt construction (carry-forward D2 from the SP10a T0 review).

## Alternatives considered

- **Bare-hostname signature** (`Classify(ctx, hostname string)`). Rejected: would force a breaking signature change to grow context. Struct fields are additively growable.
- **Pack Verdict into `Decision.Kind`** via new `KindModelTelemetry` / `KindModelMalicious` variants. Rejected for v0.2: blows the 3-file slice budget on a `kind_string.go` regen + every-switch update. SP10c MAY revisit if observability requires.
- **Wire-form enum + interface in one `pkg/model` package.** Rejected: couples adapters to the policy engine's package boundary. Separate packages keep `pkg/schema` consumable by an out-of-tree dashboard formatter without dragging in the `Classifier` interface.
- **Caller pre-clears allow/block before calling `DecideWithVerdict`.** Rejected: precedence becomes a property of the caller, not the engine; hot-reload windows during the 1–4s slow path could land new list entries between the fast-path miss and the slow-path return.

## Revisit conditions

- SP10b's adapter design finds the bounded-context shape (4–8k tokens) inadequate for prompt-injection resistance — would re-open D2 to add per-field caps or a `Truncated bool` signal field.
- SP10c's dataplane integration finds threading `Verdict` alongside `Decision` requires a coupled return type — would re-open D3 to package the two together (`Outcome` struct).
- A second model-adapter family (v0.3+) needs a schema-version field on `Input` or `Verdict` — would re-open D1/D2 with a versioning slice; pkg/schema's package doc anticipates this.

## Annexes (added 2026-05-26 — SP10b + SP10c spec promotion)

### Annex A — SP10b adapter wire format

The sibling-process adapter at `internal/model.Adapter` (`internal/model/adapter.go`) bridges `pkg/model.Classifier` to a child runtime over newline-delimited JSON on stdio. Wire format (not exported as Go types — the contract is the JSON shape):

```
stdin  (parent → child): {"hostname":"<qname>","client_hints":["..."],"user_agent":"..."}\n
stdout (child  → parent): {"verdict":"benign|telemetry|malicious"}\n
```

- One request per line; one response per line; the child MUST respond in arrival order.
- The child SHOULD log to stderr for operator visibility; stdout MUST stay pure JSON.
- Per-field caps and Unicode sanitization are the adapter's responsibility (D2 carry-forward) — `sanitize()` in `internal/model/adapter.go` enforces them before marshaling.

### Annex B — SP10b poisoned-state stance

`Adapter` exposes a one-way "poisoned" latch (`Adapter.poisoned` in `internal/model/adapter.go`). The first IO/decode error during `Classify` poisons the adapter and SIGKILLs the child; every subsequent `Classify` returns `internal/model.ErrUnavailable`. The latch is intentional: the SP10c dataplane fork treats classifier failure as terminal — one `policy: model unavailable` log line per process lifetime (invariant 7), not one per query. `Close` reaps the child unconditionally.

A future v0.3 slice MAY introduce adapter restart with backoff if operator demand surfaces; ADR-0004 D3's revisit conditions cover that scope.

### Annex C — SP10c observe-only narrowing (load-bearing for SP10e)

SP10c shipped the slow-path observe fork at `Server.classifyAsync` in `internal/dataplane/dataplane.go`. The fork:

1. Spawns asynchronously on every fast-path miss (no qname dedup in v0.2; SP10e will add learned-block matching upstream).
2. Calls `model.Classifier.Classify` against a bounded `Input{Hostname}` (SP10c does not yet populate `ClientHints` / `UserAgent`).
3. On success, calls `policy.Engine.DecideWithVerdict(qname, v)` and **logs** the resulting decision via the canonical `policy: classified` slog line:

```
msg=policy: classified  qname=<qname>  verdict=<benign|telemetry|malicious>  kind=<kind>  matched=<label>
```

The slog **attribute order matters** — `dod.sh` bullet 13 greps `qname` before `verdict`. Future code emitting `policy: classified` MUST keep this order or update the harness.

Verdict-to-log-level mapping:

| Verdict | slog level |
|---|---|
| `VerdictBenign` | `DEBUG` |
| `VerdictTelemetry` | `INFO` |
| `VerdictMalicious` | `WARN` |

4. **Does NOT apply** `Decision.Action`. SP10e is the slice that lifts this narrowing — it materializes the verdict into a runtime-mutable matcher (`internal/policy/runtime`, likely) so subsequent queries for the same qname are blocked. SP10c's invariant 1 footprint stands: model→policy is one direction, no model→connstate path on the observed query itself.

### Annex D — SP10c sibling-failure latch

`internal/dataplane` carries a `classifierDead atomic.Bool` (see SP10c Ralph N1). `errors.Is(err, model.ErrUnavailable)` `CompareAndSwap`-es from false to true on first failure; concurrent failures lose the swap and stay silent. Net: exactly one `policy: model unavailable` slog line per process lifetime (invariant 7). DOD bullet 14 asserts the count is exactly 1 after a sibling SIGKILL + post-SIGKILL probes.

## References

- `docs/engineering/decisions/ADR-0001-foundation-design.md` D2 (v0.2 scope) and D6 (license split, public-API stability)
- `docs/engineering/decisions/ADR-0003-v0.2-sub-project-decomposition.md` SP10a row
- `docs/engineering/invariants.md` invariants 1, 7, 10
- `docs/engineering/architecture.md` Tier 2 (the 4–8k token bound was removed from architecture.md when the classical detector became primary, ADR-0006)
- `docs/product/vision.md` Key Risk #6 (schema-constrained decoding)
- `pkg/model/classifier.go` (the surface)
- `pkg/schema/verdict.go` (the typed enum the surface returns)
- `Engine.DecideWithVerdict` in `internal/policy/policy.go`
