// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"encoding/json"
	"errors"
	"testing"

	"protocolward.ai/ward/pkg/schema"
)

func TestVerdict_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		v    schema.Verdict
		wire string
	}{
		{"benign", schema.VerdictBenign, `"benign"`},
		{"telemetry", schema.VerdictTelemetry, `"telemetry"`},
		{"malicious", schema.VerdictMalicious, `"malicious"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tc.v)
			if err != nil {
				t.Fatalf("Marshal(%v): unexpected error: %v", tc.v, err)
			}
			if string(got) != tc.wire {
				t.Fatalf("Marshal(%v) = %s; want %s", tc.v, got, tc.wire)
			}
			var back schema.Verdict
			if err := json.Unmarshal([]byte(tc.wire), &back); err != nil {
				t.Fatalf("Unmarshal(%s): unexpected error: %v", tc.wire, err)
			}
			if back != tc.v {
				t.Fatalf("Unmarshal(%s) = %v; want %v", tc.wire, back, tc.v)
			}
		})
	}
}

func TestParseVerdict_RejectsNonCanonical(t *testing.T) {
	t.Parallel()

	// vision.md Key Risk #6 — schema-constrained decoding. No case folding,
	// no trimming, no fallback to a default. Every non-canonical input must
	// return ErrUnknownVerdict so the policy engine cannot silently treat
	// attacker-controlled prompt-injection output as Benign.
	rows := []string{
		"BENIGN",           // uppercase
		"Benign",           // titlecase
		"",                 // empty
		"benign\n",         // trailing newline (no trimming)
		"benign ",          // trailing space
		"evil",             // unknown variant
		"benign_telemetry", // concatenation
	}
	for _, in := range rows {
		_, err := schema.ParseVerdict(in)
		if err == nil {
			t.Errorf("ParseVerdict(%q): expected error, got nil", in)
			continue
		}
		if !errors.Is(err, schema.ErrUnknownVerdict) {
			t.Errorf("ParseVerdict(%q): err = %v; want errors.Is ErrUnknownVerdict", in, err)
		}
	}
}

func TestVerdict_UnmarshalJSON_RejectsNonString(t *testing.T) {
	t.Parallel()

	// Every row MUST surface a non-nil error. Structural-JSON failures
	// (object, bareword, integer, null) may surface as *json.UnmarshalTypeError
	// or *json.SyntaxError; string-content failures (mixed case) must wrap
	// ErrUnknownVerdict.
	type row struct {
		name     string
		input    string
		mustWrap bool // must errors.Is ErrUnknownVerdict
	}
	// Note: Go's encoding/json decodes JSON null into a Go string as the
	// empty string "" — it does NOT return an error at the json layer. So
	// `null` falls through to ParseVerdict("") and is rejected via
	// ErrUnknownVerdict, not as a structural-JSON failure. mustWrap=true.
	rows := []row{
		{"integer", `1`, false},
		{"null", `null`, true},
		{"object", `{}`, false},
		{"bareword", `benign`, false},
		{"mixed_case", `"Benign"`, true},
		{"unknown_variant", `"evil"`, true},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var v schema.Verdict
			err := json.Unmarshal([]byte(tc.input), &v)
			if err == nil {
				t.Fatalf("Unmarshal(%s): expected error, got nil", tc.input)
			}
			if tc.mustWrap && !errors.Is(err, schema.ErrUnknownVerdict) {
				t.Errorf("Unmarshal(%s): err = %v; want errors.Is ErrUnknownVerdict", tc.input, err)
			}
		})
	}
}

func TestVerdict_MarshalJSON_UnknownVariant(t *testing.T) {
	t.Parallel()

	// Misuse path — Verdict(99) is not a valid variant. MarshalJSON must
	// return an error that wraps ErrUnknownVerdict so callers doing
	// errors.Is can detect schema misuse uniformly across Parse / Unmarshal /
	// Marshal paths.
	_, err := json.Marshal(schema.Verdict(99))
	if err == nil {
		t.Fatalf("Marshal(Verdict(99)): expected error, got nil")
	}
	if !errors.Is(err, schema.ErrUnknownVerdict) {
		t.Errorf("Marshal(Verdict(99)): err = %v; want errors.Is ErrUnknownVerdict", err)
	}
}

func TestVerdict_String_Stringer(t *testing.T) {
	t.Parallel()

	// stringer convention (matches internal/policy.Action) — String returns
	// the Go identifier for debug-print contexts. The wire form lives in
	// MarshalJSON, not String. A future contributor reading a verbose log
	// or a panic stack should see "VerdictMalicious", not "malicious".
	cases := []struct {
		v    schema.Verdict
		want string
	}{
		{schema.VerdictBenign, "VerdictBenign"},
		{schema.VerdictTelemetry, "VerdictTelemetry"},
		{schema.VerdictMalicious, "VerdictMalicious"},
	}
	for _, tc := range cases {
		if got := tc.v.String(); got != tc.want {
			t.Errorf("%d.String() = %q; want %q", int(tc.v), got, tc.want)
		}
	}
}

func TestVerdict_AllVariantsNamed(t *testing.T) {
	t.Parallel()

	// Iterate via stringer; stop at the first unknown variant. Upper bound
	// of 8 is generous headroom over today's 3 variants; raise with a
	// comment if a future variant pushes past 7. Same pattern as
	// internal/policy/policy_test.go:134 (function decl; guard at line 144).
	const upper = 8
	const unknownPrefix = "Verdict("
	named := 0
	for i := 0; i < upper; i++ {
		s := schema.Verdict(i).String()
		if len(s) >= len(unknownPrefix) && s[:len(unknownPrefix)] == unknownPrefix {
			break // reached past the last defined variant
		}
		if s == "" {
			t.Fatalf("Verdict(%d).String() returned empty", i)
		}
		named++
	}
	if named < 3 {
		t.Errorf("only %d Verdict variants named; spec requires Benign/Telemetry/Malicious", named)
	}
}

func TestParseVerdict_HappyPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want schema.Verdict
	}{
		{"benign", schema.VerdictBenign},
		{"telemetry", schema.VerdictTelemetry},
		{"malicious", schema.VerdictMalicious},
	}
	for _, tc := range cases {
		got, err := schema.ParseVerdict(tc.in)
		if err != nil {
			t.Errorf("ParseVerdict(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseVerdict(%q) = %v; want %v", tc.in, got, tc.want)
		}
	}
}
