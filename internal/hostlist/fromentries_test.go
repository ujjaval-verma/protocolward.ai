// SPDX-License-Identifier: Apache-2.0

package hostlist_test

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"protocolward.ai/ward/internal/hostlist"
)

func TestFromEntries_SuffixMatchWithInlineID(t *testing.T) {
	set, err := hostlist.FromEntries([]string{"example.com", "ads.example.com"})
	if err != nil {
		t.Fatalf("FromEntries: %v", err)
	}
	cases := []struct {
		q, wantMatched string
		wantOK         bool
	}{
		{"example.com", "example.com", true},
		{"x.example.com", "example.com", true},
		{"tracker.ads.example.com", "ads.example.com", true},
		{"notexample.com", "", false},
		{"example.org", "", false},
	}
	for _, tc := range cases {
		id, matched, ok := set.Match(tc.q)
		if ok != tc.wantOK || matched != tc.wantMatched {
			t.Errorf("Match(%q) = (%q, %v); want (%q, %v)", tc.q, matched, ok, tc.wantMatched, tc.wantOK)
		}
		if ok && id != hostlist.InlineSourceID {
			t.Errorf("Match(%q) id = %q; want %q", tc.q, id, hostlist.InlineSourceID)
		}
	}
}

func TestFromEntries_SharesLoadValidation(t *testing.T) {
	set, err := hostlist.FromEntries([]string{"  Ads.Example.COM.  "})
	if err != nil {
		t.Fatalf("FromEntries: %v", err)
	}
	_, matched, ok := set.Match("ads.example.com")
	if !ok || matched != "ads.example.com" {
		t.Errorf("Match = (%q, %v); want (\"ads.example.com\", true)", matched, ok)
	}
}

func TestFromEntries_NilAndEmptyYieldUsableEmptySet(t *testing.T) {
	for _, in := range [][]string{nil, {}} {
		set, err := hostlist.FromEntries(in)
		if err != nil || set == nil {
			t.Fatalf("FromEntries(%v) = (%v, %v); want non-nil empty set, nil error", in, set, err)
		}
		if _, _, ok := set.Match("example.com"); ok {
			t.Errorf("empty set matched example.com")
		}
	}
}

func TestFromEntries_DuplicatesCoalesce(t *testing.T) {
	set, err := hostlist.FromEntries([]string{"a.test", "A.TEST.", "a.test"})
	if err != nil {
		t.Fatalf("FromEntries: %v", err)
	}
	if _, _, ok := set.Match("a.test"); !ok {
		t.Error("expected hit on a.test")
	}
}

func TestInvalidEntryError_TruncatesEchoedEntry(t *testing.T) {
	long := strings.Repeat("\u00e9", 500)
	_, err := hostlist.FromEntries([]string{long})
	if err == nil {
		t.Fatal("want error")
	}
	if len(err.Error()) > 500 {
		t.Errorf("error is %d bytes; entry echo not truncated", len(err.Error()))
	}
	if !utf8.ValidString(err.Error()) {
		t.Errorf("truncation split a rune: %q", err.Error())
	}
}

func TestFromEntries_RejectsNonBareHostnames(t *testing.T) {
	rows := []struct{ name, entry string }{
		{"empty", ""},
		{"whitespace", "   "},
		{"lone_dot", "."},
		{"hosts_file_line", "0.0.0.0 ads.example.com"},
		{"adguard_rule", "||ads.example.com^"},
		{"underscore", "bad_host.example.com"},
		{"leading_hyphen", "-ads.example.com"},
		{"empty_label", "ads..example.com"},
		{"system_alias", "localhost"},
		{"non_ascii", "exämple.com"},
		{"wildcard", "*.example.com"},
		{"double_dot", "a..b"},
		{"double_trailing_dot", "a.com.."},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			set, err := hostlist.FromEntries([]string{"ok.example.com", tc.entry})
			if set != nil {
				t.Errorf("want nil set on error (no partial state), got %v", set)
			}
			var iee *hostlist.InvalidEntryError
			if !errors.As(err, &iee) {
				t.Fatalf("err = %v; want *hostlist.InvalidEntryError", err)
			}
			if iee.Index != 1 || iee.Entry != tc.entry || iee.Reason == "" {
				t.Errorf("InvalidEntryError = %+v; want Index 1, Entry %q, non-empty Reason", iee, tc.entry)
			}
			if !strings.Contains(err.Error(), "remediation") {
				t.Errorf("error lacks remediation hint (invariant #8): %v", err)
			}
		})
	}
}
