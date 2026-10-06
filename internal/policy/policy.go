// SPDX-License-Identifier: Apache-2.0

// Package policy implements the deterministic policy state engine.
//
// Engine consumes pure matcher interfaces (typically the *hostlist.Set
// returned by allowlist.Load / blocklist.Load) and produces a Decision
// describing the action the dataplane should take. The package has NO
// miekg/dns import, NO I/O, and Decide is allocation-light: zero on miss,
// one value struct on hit.
//
// # Invariants
//
//   - Invariant #1 ("the AI is a classifier, never a decider"): Engine is the
//     decider. Today wired only to static-list matchers; a future
//     DecideWithVerdict variant will consume slow-path classifier outputs
//     without dataplane churn.
//
//   - Invariant #2 ("missing handler is a compile error"): callers MUST switch
//     exhaustively on Decision.Action. The exhaustive linter
//     (.golangci.yml) is configured for policy.Action; every caller's switch
//     must also include a default: panic arm as a runtime backstop.
//
// # Precedence
//
// Decide returns Action in priority order: allow > block > forward. Allow
// wins even when block's matched suffix is more specific — operator override
// is explicit per UX invariant #7.
package policy

import (
	"fmt"

	"protocolward.ai/ward/pkg/schema"
)

//go:generate stringer -type=Action
//go:generate stringer -type=Kind

// Action is the directive returned by Decide. Adding a variant requires
// updating every switch-on-Action in the codebase (enforced at lint time by
// golangci-lint exhaustive, and at runtime by default: panic arms).
type Action int

const (
	// ActionForward means the query should be sent to the upstream pool.
	ActionForward Action = iota
	// ActionAllow means the query MATCHED the allowlist and should be forwarded.
	// Distinct from Forward so callers can emit attribution.
	ActionAllow
	// ActionBlock means the query matched the blocklist and should receive a
	// block-response (configured shape — address or NXDOMAIN).
	ActionBlock
)

// Kind discriminates which list contributed the Decision. KindNone for
// ActionForward; KindAllow / KindBlock pair with their respective Actions.
type Kind int

const (
	KindNone Kind = iota
	KindAllow
	KindBlock
)

// Decision is the pure output of Decide. ListID and MatchedLabel are empty
// when Action is ActionForward.
type Decision struct {
	Action       Action
	Kind         Kind
	ListID       string
	MatchedLabel string
}

// Matcher is the lookup-side contract Engine depends on. *hostlist.Set
// satisfies this directly. The interface lives here (not in hostlist) so
// policy has no upward import — consumer owns the abstraction.
type Matcher interface {
	Match(hostname string) (listID, matched string, ok bool)
}

// Engine is constructed once at startup and read-only thereafter. Runtime
// refresh (atomic swap) lands in slice-E.
type Engine struct {
	allow Matcher
	block Matcher
}

// NewEngine constructs an Engine. Either or both matchers may be nil.
// A nil-nil engine has pure-forwarder semantics (Decide always returns
// ActionForward).
func NewEngine(allow, block Matcher) *Engine {
	return &Engine{allow: allow, block: block}
}

// Decide consults the allowlist first, then the blocklist, then falls
// through to ActionForward. The qname is assumed pre-normalized
// (lowercase, trailing dot stripped) by the caller; empty qname returns
// ActionForward without allocation.
//
// Zero allocations on miss; one value-typed Decision on hit.
func (e *Engine) Decide(qname string) Decision {
	if qname == "" {
		return Decision{Action: ActionForward, Kind: KindNone}
	}
	if e.allow != nil {
		if id, matched, ok := e.allow.Match(qname); ok {
			return Decision{Action: ActionAllow, Kind: KindAllow, ListID: id, MatchedLabel: matched}
		}
	}
	if e.block != nil {
		if id, matched, ok := e.block.Match(qname); ok {
			return Decision{Action: ActionBlock, Kind: KindBlock, ListID: id, MatchedLabel: matched}
		}
	}
	return Decision{Action: ActionForward, Kind: KindNone}
}

// DecideWithVerdict consults the same allow/block matchers as Decide,
// then folds in a slow-path classifier's schema.Verdict. Precedence
// (UX invariant #7): allow > blocklist > model-verdict-block > forward.
//
// Allow and blocklist are re-consulted here (not assumed pre-cleared by
// the caller) so the precedence rule remains a property of the policy
// engine, not the dataplane caller. *hostlist.Set.Match("") is a no-op,
// so an empty qname falls through to the Verdict switch — Benign+empty
// forwards, Malicious/Telemetry+empty blocks. Decide retains its own
// empty-qname guard for the fast path; the divergence is deliberate
// (operator-blessed at SP10a slice 2 T0).
//
// Verdict mapping (in switch-case order so reader and code align):
//   - VerdictBenign     → ActionForward (KindNone) — Benign is a first-class
//     decision, not a fallthrough; reaching this arm means the model
//     actively cleared the destination after the lists missed.
//   - VerdictTelemetry  → ActionBlock, MatchedLabel="(model)"
//   - VerdictMalicious  → ActionBlock, MatchedLabel="(model)"
//
// Unknown variant panics via the exhaustive default arm. Schema-
// constrained decoding at the wire boundary (pkg/schema.UnmarshalJSON)
// makes that branch unreachable in well-formed flows; the panic is the
// runtime backstop against an adapter bug, not a user-input path.
func (e *Engine) DecideWithVerdict(qname string, v schema.Verdict) Decision {
	if e.allow != nil {
		if id, matched, ok := e.allow.Match(qname); ok {
			return Decision{Action: ActionAllow, Kind: KindAllow, ListID: id, MatchedLabel: matched}
		}
	}
	if e.block != nil {
		if id, matched, ok := e.block.Match(qname); ok {
			return Decision{Action: ActionBlock, Kind: KindBlock, ListID: id, MatchedLabel: matched}
		}
	}
	switch v {
	case schema.VerdictBenign:
		return Decision{Action: ActionForward, Kind: KindNone}
	case schema.VerdictTelemetry, schema.VerdictMalicious:
		return Decision{Action: ActionBlock, Kind: KindBlock, MatchedLabel: "(model)"}
	default:
		panic(fmt.Sprintf("policy: DecideWithVerdict: unknown schema.Verdict %d", int(v)))
	}
}
