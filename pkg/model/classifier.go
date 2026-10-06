// SPDX-License-Identifier: Apache-2.0

// Package model is the Apache-2.0 stable surface for the slow-path tier-2
// classifier. The deterministic policy state engine (internal/policy.Engine)
// consumes a [Classifier]'s [schema.Verdict] and decides the connection's
// [policy.Action]; this package defines the contract the engine consumes,
// nothing more.
//
// # Why pkg/model exists separately from pkg/schema
//
// pkg/schema is the wire-form enum (Benign/Telemetry/Malicious) — the
// thing the LLM returns. pkg/model is the call contract — the thing the
// dataplane invokes. Splitting them keeps the wire form independent of
// the invocation API, so an out-of-tree adapter can target the
// Classifier interface without depending on the policy engine.
//
// # Invariants
//
//   - Invariant #1 ("the AI is a classifier, never a decider"): a
//     Classifier returns a typed schema.Verdict; the decision belongs to
//     internal/policy.Engine.DecideWithVerdict. Implementations MUST NOT
//     import internal/policy, internal/dataplane, or any package that
//     mutates connection state. scripts/dod.sh bullet 12 enforces the
//     import rule at the package boundary.
//
//   - ADR-0007: pkg/model is stable public API (Apache-2.0, like the whole repository). Adding a
//     field to Input is non-breaking; renaming or removing a field is
//     not. The Classifier signature is the load-bearing surface.
//
//   - ADR-0003 SP10a: this is the second and final SP10a artifact; the
//     first (pkg/schema.Verdict) shipped in the SP10a slice 1. The first
//     implementation lands in SP10b (sibling-process adapter inside
//     internal/); SP10c wires the dataplane fork.
package model

import (
	"context"

	"protocolward.ai/ward/pkg/schema"
)

// Input is the bounded context handed to a slow-path classifier. Total
// token budget (per docs/engineering/architecture.md Tier 2) is 4-8k;
// bounding is the caller's responsibility — SP10b adapter or SP10c
// dataplane fork enforces, this package does not.
type Input struct {
	// Hostname is the caller-controlled, pre-normalized DNS name
	// (lowercase, no trailing dot) matching internal/policy.Engine's
	// qname convention.
	Hostname string
	// ClientHints carries optional protocol-level signals (e.g. ALPN,
	// SNI extras). Attacker-influenced — callers MUST sanitize and
	// length-bound before constructing Input; values flow into LLM
	// prompt context (vision.md Key Risk #6).
	ClientHints []string
	// UserAgent is the connecting client's UA string. Attacker-controlled
	// — callers MUST sanitize and length-bound before constructing Input;
	// value flows into LLM prompt context (vision.md Key Risk #6).
	UserAgent string
}

// Classifier is the slow-path tier-2 contract. Implementations MUST be
// safe for concurrent Classify calls (the dataplane fork in SP10c
// dispatches without holding a lock). They MUST NOT touch connection
// state or call into internal/policy.Engine — invariant 1.
//
// On success the returned schema.Verdict is one of the defined variants
// (Benign/Telemetry/Malicious) and err is nil. A non-nil err signals
// either an infrastructure failure (model process unavailable, timeout,
// context cancellation, etc.) or an input the implementation refuses to
// score. Implementations expose input errors as sentinels (for example
// detect.ErrInvalidHostname) so callers can tell them apart with
// errors.Is; callers MUST NOT treat an input error as the model being
// unavailable. Either way the returned Verdict is unspecified when err is
// non-nil and the caller MUST NOT consume it. Wire-form parsing happens
// upstream in pkg/schema; schema.ErrUnknownVerdict will not appear at
// this boundary.
type Classifier interface {
	Classify(ctx context.Context, in Input) (schema.Verdict, error)
}

// Assessor is the optional explained form of a [Classifier]. A Classifier
// MAY also implement Assessor; callers type-assert for it and fall back to
// Classify when it is absent. For an implementation of both, Classify
// MUST return the same Verdict as Assess for the same Input. The same
// concurrency and invariant-1 rules as Classifier apply: Assess returns
// data and never touches connection state. A non-nil err means the
// returned Assessment MUST NOT be consumed.
type Assessor interface {
	Assess(ctx context.Context, in Input) (schema.Assessment, error)
}
