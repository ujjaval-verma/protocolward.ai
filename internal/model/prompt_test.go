// SPDX-License-Identifier: Apache-2.0

package model_test

import (
	"reflect"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/model"
	pkgmodel "protocolward.ai/ward/pkg/model"
)

func TestStripControl(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain ascii", "hello world", "hello world"},
		{"tab kept", "a\tb", "a\tb"},
		{"newline dropped", "a\nb", "ab"},
		{"carriage return dropped", "a\rb", "ab"},
		{"NUL dropped", "a\x00b", "ab"},
		{"zero-width space dropped", "a​b", "ab"},
		{"BEL dropped", "a\x07b", "ab"},
		{"UTF-8 multibyte rune kept", "hello é world", "hello é world"},
		{"emoji kept (not a control rune)", "hi \U0001f600", "hi \U0001f600"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := model.StripControl(tc.in)
			if got != tc.want {
				t.Errorf("StripControl(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBoundString_BelowCap(t *testing.T) {
	got := model.BoundString("abc", 10)
	if got != "abc" {
		t.Errorf("BoundString(abc, 10) = %q, want %q", got, "abc")
	}
}

func TestBoundString_AtCap(t *testing.T) {
	got := model.BoundString("abcde", 5)
	if got != "abcde" {
		t.Errorf("BoundString(abcde, 5) = %q, want %q", got, "abcde")
	}
}

func TestBoundString_OverCap(t *testing.T) {
	got := model.BoundString("abcdefghij", 4)
	if got != "abcd" {
		t.Errorf("BoundString(abcdefghij, 4) = %q, want %q", got, "abcd")
	}
}

func TestBoundString_ZeroCap(t *testing.T) {
	got := model.BoundString("abcdef", 0)
	if got != "" {
		t.Errorf("BoundString(abcdef, 0) = %q, want %q", got, "")
	}
}

func TestBoundString_TornUTF8AcceptableForAttackerString(t *testing.T) {
	// "héllo" — the é is two bytes (\xc3\xa9). Capping at 2 bytes truncates
	// inside the rune; the spec accepts torn UTF-8 on attacker-controlled
	// strings (it's their problem if the truncation hurts; we won't allocate
	// to decode-and-round).
	got := model.BoundString("héllo", 2)
	if len(got) != 2 {
		t.Errorf("BoundString len = %d, want 2 (byte-boundary cap)", len(got))
	}
}

func TestSanitize_NoMutationOfInput(t *testing.T) {
	original := pkgmodel.Input{
		Hostname:    "example.com",
		ClientHints: []string{"hint-a", "hint-b"},
		UserAgent:   "Mozilla/5.0",
	}
	originalCopy := pkgmodel.Input{
		Hostname:    original.Hostname,
		ClientHints: append([]string(nil), original.ClientHints...),
		UserAgent:   original.UserAgent,
	}
	_ = model.Sanitize(original)
	if !reflect.DeepEqual(original, originalCopy) {
		t.Errorf("Sanitize mutated input: got %+v, want %+v", original, originalCopy)
	}
}

func TestSanitize_StripsControlRunesFromAllStringFields(t *testing.T) {
	in := pkgmodel.Input{
		Hostname:    "evil\n.example.com",
		ClientHints: []string{"hint\x00a", "hint\rb"},
		UserAgent:   "Mozilla\n/5.0",
	}
	got := model.Sanitize(in)
	if strings.ContainsAny(got.Hostname, "\n\r\x00") {
		t.Errorf("Hostname not stripped: %q", got.Hostname)
	}
	for i, h := range got.ClientHints {
		if strings.ContainsAny(h, "\n\r\x00") {
			t.Errorf("ClientHints[%d] not stripped: %q", i, h)
		}
	}
	if strings.ContainsAny(got.UserAgent, "\n\r\x00") {
		t.Errorf("UserAgent not stripped: %q", got.UserAgent)
	}
}

func TestSanitize_BoundsHostnameToMaxHostnameLen(t *testing.T) {
	long := strings.Repeat("a", model.MaxHostnameLen+50)
	got := model.Sanitize(pkgmodel.Input{Hostname: long})
	if len(got.Hostname) != model.MaxHostnameLen {
		t.Errorf("Hostname len = %d, want %d", len(got.Hostname), model.MaxHostnameLen)
	}
}

func TestSanitize_BoundsUserAgentToMaxUserAgentLen(t *testing.T) {
	long := strings.Repeat("u", model.MaxUserAgentLen+50)
	got := model.Sanitize(pkgmodel.Input{UserAgent: long})
	if len(got.UserAgent) != model.MaxUserAgentLen {
		t.Errorf("UserAgent len = %d, want %d", len(got.UserAgent), model.MaxUserAgentLen)
	}
}

func TestSanitize_BoundsEachClientHintToMaxClientHintLen(t *testing.T) {
	long := strings.Repeat("c", model.MaxClientHintLen+50)
	got := model.Sanitize(pkgmodel.Input{ClientHints: []string{long, "short"}})
	if len(got.ClientHints) != 2 {
		t.Fatalf("ClientHints len = %d, want 2", len(got.ClientHints))
	}
	if len(got.ClientHints[0]) != model.MaxClientHintLen {
		t.Errorf("ClientHints[0] len = %d, want %d", len(got.ClientHints[0]), model.MaxClientHintLen)
	}
	if got.ClientHints[1] != "short" {
		t.Errorf("ClientHints[1] = %q, want %q", got.ClientHints[1], "short")
	}
}

func TestSanitize_CapsClientHintsSliceAtMaxClientHints(t *testing.T) {
	in := make([]string, model.MaxClientHints+5)
	for i := range in {
		in[i] = "hint"
	}
	got := model.Sanitize(pkgmodel.Input{ClientHints: in})
	if len(got.ClientHints) != model.MaxClientHints {
		t.Errorf("ClientHints len = %d, want %d", len(got.ClientHints), model.MaxClientHints)
	}
}

func TestSanitize_KeepsEmptyClientHintEntries(t *testing.T) {
	// A caller passing an empty string in ClientHints is signaling something
	// (e.g. "this position is the SNI extras field but we didn't get any").
	// Dropping empties would lose that positional information.
	got := model.Sanitize(pkgmodel.Input{ClientHints: []string{"a", "", "b"}})
	want := []string{"a", "", "b"}
	if !reflect.DeepEqual(got.ClientHints, want) {
		t.Errorf("ClientHints = %v, want %v", got.ClientHints, want)
	}
}

func TestSanitize_NilClientHintsStaysNilOrEmpty(t *testing.T) {
	got := model.Sanitize(pkgmodel.Input{Hostname: "ex.com"})
	if len(got.ClientHints) != 0 {
		t.Errorf("ClientHints len = %d, want 0", len(got.ClientHints))
	}
}
