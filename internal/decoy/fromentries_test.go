// SPDX-License-Identifier: Apache-2.0

package decoy_test

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"protocolward.ai/ward/internal/decoy"
	"protocolward.ai/ward/internal/hostlist"
)

func TestFromEntries_ExactMatchWithInlineID(t *testing.T) {
	set, err := decoy.FromEntries([]string{"NAS-Backup.home.arpa.", "printer-admin.lan"})
	if err != nil {
		t.Fatalf("FromEntries: %v", err)
	}
	id, matched, ok := set.Match("nas-backup.home.arpa")
	if !ok || matched != "nas-backup.home.arpa" || id != hostlist.InlineSourceID {
		t.Errorf("Match = (%q, %q, %v); want (%q, \"nas-backup.home.arpa\", true)", id, matched, ok, hostlist.InlineSourceID)
	}
	if _, _, ok := set.Match("PRINTER-ADMIN.LAN."); !ok {
		t.Error("expected case/trailing-dot tolerant hit on printer-admin.lan")
	}
	for _, miss := range []string{"scanner.nas-backup.home.arpa", "home.arpa", "admin.lan"} {
		if _, _, ok := set.Match(miss); ok {
			t.Errorf("Match(%q) hit; decoys are exact-match only", miss)
		}
	}
}

func TestFromEntries_NilAndEmptyYieldUsableEmptySet(t *testing.T) {
	for _, in := range [][]string{nil, {}} {
		set, err := decoy.FromEntries(in)
		if err != nil || set == nil {
			t.Fatalf("FromEntries(%v) = (%v, %v); want non-nil empty set, nil error", in, set, err)
		}
		if _, _, ok := set.Match("nas-backup.home.arpa"); ok {
			t.Error("empty set matched")
		}
	}
}

// Parity with the decoy file parser, which accepts any single field: an
// underscore label (e.g. a planted _ldap SRV-style name) is a legal decoy.
func TestFromEntries_AcceptsUnderscoreLabels(t *testing.T) {
	set, err := decoy.FromEntries([]string{"_ldap.corp.lan"})
	if err != nil {
		t.Fatalf("FromEntries: %v", err)
	}
	if _, _, ok := set.Match("_ldap.corp.lan"); !ok {
		t.Error("expected hit on _ldap.corp.lan")
	}
}

func TestFromEntries_RejectsNonHostnames(t *testing.T) {
	rows := []struct{ name, entry string }{
		{"empty", ""},
		{"whitespace", "   "},
		{"lone_dot", "."},
		{"two_words", "0.0.0.0 nas.lan"},
		{"comment", "nas.lan#planted"},
		{"leading_dot", ".nas.lan"},
		{"empty_label", "nas..lan"},
		{"double_trailing_dot", "a.com.."},
		{"non_ascii", "ex\u00e4mple.lan"},
		{"punctuation", "nas!.lan"},
		{"leading_hyphen", "-x.lan"},
		{"trailing_hyphen", "x-.lan"},
		{"label_64", strings.Repeat("a", 64) + ".lan"},
		{"name_254", strings.Repeat("a.", 127) + "bc"},
		{"name_1000", strings.Repeat("a", 1000)},
		{"vertical_tab", "a\vb.lan"},
		{"form_feed", "a\fb.lan"},
		{"nul", "a\x00b.lan"},
		{"nbsp_inside", "a\u00a0b.lan"},
		{"nel_inside", "a\u0085b.lan"},
		{"inner_tab", "a\tb.lan"},
		{"inner_newline", "a\nb.lan"},
		{"lone_surrogate", "a\xed\xa0\x80.lan"},
		{"wildcard", "*.nas.lan"},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			set, err := decoy.FromEntries([]string{"ok.lan", tc.entry})
			if set != nil {
				t.Errorf("want nil set on error (no partial state), got %v", set)
			}
			var iee *decoy.InvalidEntryError
			if !errors.As(err, &iee) {
				t.Fatalf("err = %v; want *decoy.InvalidEntryError", err)
			}
			if iee.Index != 1 || iee.Entry != tc.entry {
				t.Errorf("InvalidEntryError = %+v; want Index 1, Entry %q", iee, tc.entry)
			}
			if !strings.Contains(err.Error(), "remediation") {
				t.Errorf("error lacks remediation hint (invariant #8): %v", err)
			}
		})
	}
}

// Boundary values at the DNS limits are accepted (and match), so the gate
// is not over-strict.
func TestFromEntries_AcceptsDNSLimits(t *testing.T) {
	label63 := strings.Repeat("a", 63) + ".lan"
	name253 := strings.Repeat("a.", 126) + strings.Repeat("b", 1) // 253 bytes
	if len(name253) != 253 {
		t.Fatalf("test setup: name253 len = %d", len(name253))
	}
	for _, e := range []string{label63, name253, "a-b.lan", "0.lan", "_x._tcp.lan"} {
		set, err := decoy.FromEntries([]string{e})
		if err != nil {
			t.Errorf("FromEntries(%q): %v", e, err)
			continue
		}
		if _, _, ok := set.Match(e); !ok {
			t.Errorf("accepted entry %q does not match itself", e)
		}
	}
}

func TestFromEntries_DuplicatesCoalesce(t *testing.T) {
	set, err := decoy.FromEntries([]string{"a.lan", "A.LAN.", "a.lan"})
	if err != nil {
		t.Fatalf("FromEntries: %v", err)
	}
	if _, _, ok := set.Match("a.lan"); !ok {
		t.Error("expected hit on a.lan")
	}
}

func TestFromEntries_FirstInvalidWins(t *testing.T) {
	_, err := decoy.FromEntries([]string{"ok.lan", "bad host", "-also-bad.lan"})
	var iee *decoy.InvalidEntryError
	if !errors.As(err, &iee) || iee.Index != 1 {
		t.Fatalf("err = %v; want InvalidEntryError at index 1", err)
	}
}

func TestInvalidEntryError_TruncatesEchoedEntry(t *testing.T) {
	long := strings.Repeat("\u00e9", 500) // 1000 bytes, multi-byte runes
	_, err := decoy.FromEntries([]string{long})
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	if len(msg) > 400 {
		t.Errorf("error is %d bytes; entry echo not truncated", len(msg))
	}
	if !utf8.ValidString(msg) {
		t.Errorf("truncation split a rune: %q", msg)
	}
	var iee *decoy.InvalidEntryError
	if !errors.As(err, &iee) || iee.Entry != long {
		t.Error("Entry field must keep the full value")
	}
}
