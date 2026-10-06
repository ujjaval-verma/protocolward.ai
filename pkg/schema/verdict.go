// SPDX-License-Identifier: Apache-2.0

// Package schema is the contract between unpredictable LLM output and
// deterministic Go control flow. Slow-path classifiers (pkg/model.Classifier,
// landing in the next SP10a slice) return a [Verdict]; internal/policy maps
// the Verdict to a policy.Action.
//
// # Schema-constrained decoding
//
// Per vision.md Key Risk #6, the wire form is a fixed lowercase enum
// ("benign", "telemetry", "malicious"); ParseVerdict and UnmarshalJSON reject
// every other input with [ErrUnknownVerdict] — no case folding, no trimming,
// no fallback. A flipped attacker-controlled label still has to map to a
// handler that does something the attacker wants; rejection at the schema
// boundary is the first backstop.
//
// # Versioning
//
// This package does NOT carry a schema_version field today. When v0.3
// introduces a second model-adapter family alongside Gemma 4, a future slice
// adds versioning; see docs/engineering/testing.md (pkg/schema row,
// out-of-scope column).
//
// # Invariants
//
//   - Invariant #1 ("the AI is a classifier, never a decider"): Verdict is a
//     pure data type; no method here routes execution or calls into the
//     policy engine. internal/policy is the decider.
//   - ADR-0007: pkg/schema is stable public API (Apache-2.0, like the whole repository).
//   - ADR-0003 SP10a: this package is one of two artifacts in SP10a (model
//     contracts). The Classifier interface lands in the next slice.
package schema

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrUnknownVerdict is returned by ParseVerdict and UnmarshalJSON for any
// input that is not exactly one of the canonical wire forms ("benign",
// "telemetry", "malicious"). Schema-constrained decoding — vision.md Key
// Risk #6 — requires that unknown values be rejected rather than silently
// mapped to a default; the policy engine must never receive a fabricated
// Benign verdict because the classifier returned a malformed string.
var ErrUnknownVerdict = errors.New("schema: unknown verdict")

//go:generate stringer -type=Verdict

// Verdict is the typed enum returned by a slow-path classifier. Adding a
// variant requires updating canonicalName, ParseVerdict, the variant-count
// ward test, and every switch-on-Verdict in downstream consumers (enforced
// at lint time by the exhaustive linter — .golangci.yml).
type Verdict int

const (
	// VerdictBenign means no policy action — the dataplane forwards
	// the request unchanged.
	VerdictBenign Verdict = iota
	// VerdictTelemetry means the classifier identified the destination
	// as ad / tracker / metrics traffic. internal/policy maps to ActionBlock.
	VerdictTelemetry
	// VerdictMalicious means the classifier identified the destination
	// as malware / phishing / C2 traffic. internal/policy maps to ActionBlock
	// and the connection is severed.
	VerdictMalicious
)

func canonicalName(v Verdict) (string, bool) {
	switch v {
	case VerdictBenign:
		return "benign", true
	case VerdictTelemetry:
		return "telemetry", true
	case VerdictMalicious:
		return "malicious", true
	}
	return "", false
}

func ParseVerdict(s string) (Verdict, error) {
	switch s {
	case "benign":
		return VerdictBenign, nil
	case "telemetry":
		return VerdictTelemetry, nil
	case "malicious":
		return VerdictMalicious, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrUnknownVerdict, s)
}

func (v Verdict) MarshalJSON() ([]byte, error) {
	name, ok := canonicalName(v)
	if !ok {
		return nil, fmt.Errorf("schema: marshal verdict: unknown variant %d: %w", int(v), ErrUnknownVerdict)
	}
	return []byte(`"` + name + `"`), nil
}

func (v *Verdict) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	got, err := ParseVerdict(s)
	if err != nil {
		return err
	}
	*v = got
	return nil
}
