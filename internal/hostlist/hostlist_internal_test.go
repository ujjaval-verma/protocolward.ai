// SPDX-License-Identifier: Apache-2.0

package hostlist

import "testing"

func TestParseLine(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantOK   bool
		wantWarn bool // true means reason != ""
	}{
		// silent skips
		{"", "", false, false},
		{"   ", "", false, false},
		{"# comment", "", false, false},
		{"   # indented", "", false, false},
		// happy path
		{"0.0.0.0 example.com", "example.com", true, false},
		{"127.0.0.1 example.com", "example.com", true, false},
		{"0.0.0.0   example.com  ", "example.com", true, false},
		{"0.0.0.0 EXAMPLE.com", "example.com", true, false},
		{"0.0.0.0 example.com.", "example.com", true, false},
		// rejects with WARN
		{"1.2.3.4 example.com", "", false, true},
		{"::1 example.com", "", false, true},
		{"0.0.0.0 a.com b.com", "", false, true},
		// AdGuard ||hostname^ form
		{"||double-click.net^", "double-click.net", true, false},
		{"||example.com^", "example.com", true, false},
		{"||EXAMPLE.com^", "example.com", true, false},
		{"||example.com.^", "example.com", true, false},
		{"||example.com", "", false, true},            // missing trailing ^
		{"||^", "", false, true},                      // empty host
		{"||example..com^", "", false, true},          // invalid host (consecutive dots)
		{"@@||example.com^", "", false, true},         // exception, not supported
		{"||example.com^$important", "", false, true}, // modifier, not supported
		{"||localhost^", "", false, true},             // system alias
		{"||example.com^^", "", false, true},          // double caret (T6 N2)
		{"||", "", false, true},                       // bare double-pipe (T6 N3)
		// AdAway "0 hostname" form
		{"0 example.com", "example.com", true, false},
		{"0   EXAMPLE.com  ", "example.com", true, false},
		{"0 localhost", "", false, true},
		{":: example.com", "", false, true},
		{"0 example.com extra", "", false, true},
		{"0.0.0.0 example..com", "", false, true},
		{"0.0.0.0 -bad.example.com", "", false, true},
		{"0.0.0.0 bad-.example.com", "", false, true},
		{"0.0.0.0 例え.com", "", false, true},
		{"0.0.0.0 localhost", "", false, true},
		{"0.0.0.0 localhost.localdomain", "", false, true},
		{"0.0.0.0 broadcasthost", "", false, true},
	}
	for _, c := range cases {
		gotHost, gotOK, gotReason := parseLine(c.in)
		if gotOK != c.wantOK || gotHost != c.wantHost {
			t.Errorf("parseLine(%q): got (%q, %v), want (%q, %v)", c.in, gotHost, gotOK, c.wantHost, c.wantOK)
		}
		if (gotReason != "") != c.wantWarn {
			t.Errorf("parseLine(%q): got reason=%q, want wantWarn=%v", c.in, gotReason, c.wantWarn)
		}
	}
}

func TestNormalizeHostname(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"example.com", "example.com", true},
		{"EXAMPLE.COM", "example.com", true},
		{"example.com.", "example.com", true},
		{"  example.com  ", "example.com", true},
		{"", "", false},
		{".", "", false},
		{"example..com", "", false},
		{"-bad.com", "", false},
		{"bad-.com", "", false},
		{"a-.b", "", false},
		{"a.-b", "", false},
		{"例え.com", "", false},
		{"foo/bar", "", false},
	}
	for _, c := range cases {
		got, ok := normalizeHostname(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("normalizeHostname(%q): got (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestIsSystemAlias(t *testing.T) {
	for _, n := range []string{"localhost", "localhost.localdomain", "broadcasthost"} {
		if !isSystemAlias(n) {
			t.Errorf("isSystemAlias(%q) = false, want true", n)
		}
	}
	for _, n := range []string{"example.com", "broadcast", "localhostx"} {
		if isSystemAlias(n) {
			t.Errorf("isSystemAlias(%q) = true, want false", n)
		}
	}
}

func TestFromEntries_DuplicatesCoalesceToOneEntry(t *testing.T) {
	set, err := FromEntries([]string{"a.test", "A.TEST.", "a.test"})
	if err != nil {
		t.Fatalf("FromEntries: %v", err)
	}
	if got := len(set.entries); got != 1 {
		t.Errorf("entries = %d; want 1", got)
	}
}
