// SPDX-License-Identifier: Apache-2.0

package hostlist_test

import (
	"strings"
	"testing"

	"protocolward.ai/ward/internal/hostlist"
)

// nameOf builds a dotted name of exactly n bytes from labels of at most 63 bytes.
func nameOf(t *testing.T, n int) string {
	t.Helper()
	var labels []string
	rem := n
	for rem > 64 {
		labels = append(labels, strings.Repeat("a", 63))
		rem -= 64
	}
	if rem < 1 {
		t.Fatalf("cannot build a %d-byte name", n)
	}
	labels = append(labels, strings.Repeat("b", rem))
	name := strings.Join(labels, ".")
	if len(name) != n {
		t.Fatalf("built %d bytes, want %d", len(name), n)
	}
	return name
}

func TestNormalizeName(t *testing.T) {
	l63 := strings.Repeat("a", 63)
	l64 := strings.Repeat("a", 64)
	n253, n254 := nameOf(t, 253), nameOf(t, 254)
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"plain", "example.com", "example.com", true},
		{"upper_folded", "EXAMPLE.COM", "example.com", true},
		{"trailing_dot_stripped", "example.com.", "example.com", true},
		{"two_trailing_dots", "example.com..", "", false},
		{"surrounding_space", "  example.com  ", "example.com", true},
		{"leading_space", " a.com", "a.com", true},
		{"inner_space", "a b.com", "", false},
		{"empty", "", "", false},
		{"lone_dot", ".", "", false},
		{"empty_label", "example..com", "", false},
		{"leading_dot", ".example.com", "", false},
		{"leading_hyphen", "-bad.com", "", false},
		{"trailing_hyphen", "bad-.com", "", false},
		{"hyphen_end_label", "a-.b", "", false},
		{"hyphen_start_label", "a.-b", "", false},
		{"inner_hyphen", "a-b.com", "a-b.com", true},
		{"underscore", "_ldap.corp.lan", "_ldap.corp.lan", true},
		{"underscore_inner", "bad_host.example.com", "bad_host.example.com", true},
		{"label_63", l63 + ".com", l63 + ".com", true},
		{"label_64", l64 + ".com", "", false},
		{"name_253", n253, n253, true},
		{"name_253_trailing_dot", n253 + ".", n253, true},
		{"name_254", n254, "", false},
		{"non_ascii_cjk", "例え.com", "", false},
		{"kelvin_sign", "Ka.com", "", false},
		{"dotted_capital_i", "İx.com", "", false},
		{"nbsp_trimmed", " a.com", "a.com", true},
		{"nbsp_inside", "a b.com", "", false},
		{"slash", "foo/bar", "", false},
		{"wildcard", "*.example.com", "", false},
		{"bang", "nas!.lan", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := hostlist.NormalizeName(c.in)
			if ok != c.ok || got != c.want {
				t.Errorf("NormalizeName(%q): got (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
			}
		})
	}
	if hostlist.MaxNameLen != 253 || hostlist.MaxLabelLen != 63 {
		t.Errorf("limits = %d/%d, want 253/63", hostlist.MaxNameLen, hostlist.MaxLabelLen)
	}
}

func TestFoldName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"example.com.", "example.com"},
		{"Example.Com.", "example.com"},
		{"a.com..", "a.com."},
		{" a.com", " a.com"}, // no trimming
		{".", ""},
		{"", ""},
		{"\xff\xfeA.com", "\xff\xfea.com"}, // invalid UTF-8 (ToLower maps it to U+FFFD)
		{"Ka.com", "ka.com"},
	}
	for _, c := range cases {
		want := strings.ToLower(strings.TrimSuffix(c.in, "."))
		if got := hostlist.FoldName(c.in); got != want {
			t.Errorf("FoldName(%q) = %q, differs from inline ToLower/TrimSuffix %q", c.in, got, want)
		}
	}
	// Explicit expectations for the ASCII rows (the invalid-UTF-8 and Kelvin
	// rows are covered by the parity check above).
	for _, c := range cases[:7] {
		if got := hostlist.FoldName(c.in); got != c.want {
			t.Errorf("FoldName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFoldName_NoAllocWhenFolded(t *testing.T) {
	for _, in := range []string{"example.com", "example.com."} {
		var sink string
		allocs := testing.AllocsPerRun(100, func() { sink = hostlist.FoldName(in) })
		if allocs != 0 {
			t.Errorf("FoldName(%q) allocs = %v, want 0", in, allocs)
		}
		_ = sink
	}
}
