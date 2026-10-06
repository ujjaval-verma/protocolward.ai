# ADR-0006 — Hybrid classifier direction: classical on-device detector first

- **Status:** Accepted
- **Date:** 2026-10-05
- **Author:** Ujjaval Verma
- **Spec:** public-beta launch design notes §1 D1/D6/D7 and §3 S1 (internal, not published); this ADR is the durable summary
- **Amends:** ADR-0004 (Classifier contract) — additive only; `model.Classifier`, `model.Input` and `schema.Verdict` are unchanged.

## Context

ADR-0004 shaped the slow-path contract around a sibling-process LLM adapter (Gemma). For the public beta we need a detector that runs everywhere Ward runs — including the browser demo compiled to WebAssembly — with no model download, no sibling process and an explanation a user can read. A small classical detector does that today; an LLM remains useful as an optional explainer later.

## Decision

### D1 — The primary behavioural classifier is a classical, on-device lexical detector

`pkg/detect.Lexical` (Apache-2.0, stdlib only, no I/O, wasm-safe) scores the registrable label of a hostname with five features — character-trigram surprisal, Shannon entropy, digit ratio, longest consonant run and label length — combined linearly into a Score in [0,1]; Score ≥ T_mal (0.50 at launch, tuned on `testdata/eval/lexical-v1.jsonl`) is `VerdictMalicious`, otherwise `VerdictBenign`. Single-label names, names under local-use TLDs (`local`, `lan`, `home`, `internal`, `localdomain`, `localhost`, plus the never-delegated and reserved `corp`, `mail`, `intranet`, `private`, `domain`, `workgroup`, `test`, `example`, `invalid`) or `home.arpa`, reverse-DNS names and punycode labels are not scored (they are not registered domains, or not representable in the model). It never emits `VerdictTelemetry` (lists own telemetry). v1 is hostname-only; timing and per-device history are "coming soon".

### D2 — `schema.Assessment` and the optional `model.Assessor` (amends ADR-0004 D1)

`schema.Assessment{Verdict, Score, Reasons}` with `schema.Reason{Code, Detail, Weight}` and five stable reason codes (`high_entropy`, `rare_ngrams`, `digit_heavy`, `consonant_run`, `long_label`). `model.Assessor` is an optional second interface: a Classifier MAY implement it; callers type-assert. For an implementation of both, `Classify` returns `Assess(...).Verdict`. The `model.Classifier` error contract is widened: besides infrastructure failure, a non-nil error may be an input the implementation refuses to score, exposed as a sentinel (`detect.ErrInvalidHostname`) that callers distinguish with `errors.Is` and never treat as the model being unavailable. Reasons are sorted by Weight descending and are nil for a Benign assessment with Score < 0.2. `Detail` is ≤ 120 bytes and never contains attacker-controlled text. Invariant 1 is unchanged: Assessment is data; `internal/policy` decides.

### D3 — Flag-only in the beta

Detector verdicts are logged and surfaced (the dashboard "Flags" panel) but never enforced. Enforcement remains ADR-0003 SP10e scope and needs its own ADR.

### D4 — The LLM becomes an optional explainer; terminology

The sibling-process adapter from ADR-0004 Annex A/B stays as the extension point for an optional LLM explainer. Going forward, docs call it the **reference sibling adapter** rather than "the Gemma adapter"; no model family is a default. Existing accepted ADRs are not rewritten; tracked docs are updated in S4's doc-drift pass.

### D5 — JEPA-style learned representations are a research track only

Nothing ships from it in the beta; any future promotion needs its own ADR and eval evidence against `lexical-v1`.

### D6 — Training-data provenance

The trigram table is derived from the Majestic Million (CC BY 3.0) by `scripts/build-ngrams`; attribution and modification notice live in `pkg/detect/NOTICE`. Cisco Umbrella (no licence grant) and Tranco (inherits CC BY-NC and CC BY-SA components) were rejected. DGA eval names come from two public algorithms (the Wikipedia reference DGA and Ramnit) plus a Bamital-shaped MD5-hex generator; the MD5 family is a synthetic, not the published Bamital algorithm (no third-party data).

## Consequences

- `pkg/detect` is the first in-tree `model.Classifier` that runs in-process; `ward serve` wires it in (`model: {builtin: lexical}`), and the wasm demo uses it too.
- `ward eval --builtin` measures the real detector; acceptance is DGA recall ≥ 0.85 and benign FPR ≤ 1%.
- Measured (2026-10-05): DGA recall 0.909 overall / 0.864 excluding the trivially separable hex family (`dga-md5`); `TestEvalBuiltinLexicalTargets` also gates the wiki+ramnit recall at 0.85 so md5 cannot mask a regression. Thresholds are unchanged.
- Benign-FPR caveat: 29% (588/1998) of held-out benign first labels also appear in the training labels at other ranks (ranks themselves are disjoint), so the 0.0060 lexical-v1 FPR is in-distribution. The honest figure is the out-of-sample 0.0080 (ranks 200k-300k). lexical-v2 should exclude held-out labels from training.
- Known blind spot: dictionary-word DGAs. Known honest limit: short random-looking brands and pinyin abbreviations sit near the threshold.

## Alternatives considered

- **LLM-first (Gemma) as the only behavioural signal.** Rejected for beta: model download, sibling process, latency, and it cannot run in the browser demo.
- **Embedding a trained neural model.** Rejected: dependencies and binary size, opaque reasons, wasm budget.
- **Scoring the longest label rather than the registrable label.** Rejected: flags CDN hash subdomains under legitimate brands.

## Revisit conditions

- Eval recall/FPR regress below target on a refreshed Majestic snapshot.
- Timing / per-device signals land (would extend Assessment reasons, not replace the contract).
- Enforcement mode (ADR-0003 SP10e) is scheduled.
