// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"context"
	"errors"
	"strings"
	"testing"

	"protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

func TestAssess_RejectsInvalidHostnames(t *testing.T) {
	cases := map[string]string{
		"empty":               "",
		"lone dot":            ".",
		"empty label":         "a..b",
		"leading dot":         ".example.com",
		"over 253 bytes":      strings.Repeat("a.", 127) + "com",
		"label over 63 bytes": strings.Repeat("a", 64) + ".com",
		"leading hyphen":      "-a.com",
		"trailing hyphen":     "a-.com",
		"space":               "exa mple.com",
		"at sign":             "ex@mple.com",
		"at sign short":       "a@b.com",
		"non-ascii umlaut":    "bücher.de",
		"non-ascii":           "münchen.de",
		"ipv4 literal":        "192.168.1.1",
		"numeric tld":         "example.123",
		"ipv6 literal":        "::1",
		"control byte":        "exa\x00mple.com",
		"kelvin sign":         "\u212Aelvin.com",
		"dotted capital I":    "İstanbul.com",
	}
	l := New()
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := l.Assess(context.Background(), model.Input{Hostname: h})
			if !errors.Is(err, ErrInvalidHostname) {
				t.Fatalf("Assess(%q) err = %v, want ErrInvalidHostname", h, err)
			}
			if h != "" && h != "." && strings.Contains(err.Error(), h) {
				t.Errorf("error %q echoes the input hostname", err)
			}
			if _, cerr := l.Classify(context.Background(), model.Input{Hostname: h}); !errors.Is(cerr, ErrInvalidHostname) {
				t.Errorf("Classify(%q) err = %v, want ErrInvalidHostname", h, cerr)
			}
		})
	}
}

func TestAssess_AcceptsEdgeValidHostnames(t *testing.T) {
	ok := []string{
		"Google.COM.",                     // case + trailing dot normalised
		"_dmarc.example.com",              // underscore labels (SRV/TXT)
		strings.Repeat("a", 63) + ".com",  // 63-byte label
		strings.Repeat("a.", 125) + "com", // exactly 253 bytes
		"localhost",                       // single label
		"wpad",                            // single label
	}
	l := New()
	for _, h := range ok {
		if _, err := l.Assess(context.Background(), model.Input{Hostname: h}); err != nil {
			t.Errorf("Assess(%q) err = %v, want nil", h, err)
		}
	}
}

func TestAssess_NormalisesCaseAndTrailingDot(t *testing.T) {
	l := New()
	a, _ := l.Assess(context.Background(), model.Input{Hostname: "QWKJXZPVTR.NET."})
	b, _ := l.Assess(context.Background(), model.Input{Hostname: "qwkjxzpvtr.net"})
	if a.Score != b.Score || a.Verdict != b.Verdict {
		t.Errorf("upper+dot = %+v, lower = %+v; want identical", a, b)
	}
}

func TestRegistrableLabel(t *testing.T) {
	cases := []struct {
		host  string
		label string
		score bool
	}{
		{"google.com", "google", true},
		{"fonts.gstatic.com", "gstatic", true},
		{"d1x2y3.cloudfront.net", "cloudfront", true},
		{"bbc.co.uk", "bbc", true},
		{"news.bbc.co.uk", "bbc", true},
		{"co.uk", "co", true},
		{"localhost", "", false},
		{"wpad", "", false},
		{"desktop-7h3k2l9", "", false},
		{"desktop-7h3k2l9.lan", "", false},
		{"android-1a2b3c4d5e6f7a8b.local", "", false},
		{"nas.internal", "", false},
		{"router.home", "", false},
		{"nas-backup.home.arpa", "", false},
		{"printer-admin.lan", "", false},
		{"lan.example.com", "example", true},
		{"1.1.168.192.in-addr.arpa", "", false},
		{"b.a.9.8.ip6.arpa", "", false},
		{"xn--80ak6aa92e.com", "", false},
		{"www.xn--80ak6aa92e.com", "", false},
		{"xn--abc", "", false},
		{"in-addr.arpa", "", false},
		{"ip6.arpa", "", false},
		{"home.arpa", "", false},
		{"desktop-7h3k2l9.corp", "", false},
		{"desktop-7h3k2l9.test", "", false},
	}
	for _, c := range cases {
		labels, err := validate(c.host)
		if err != nil {
			t.Fatalf("validate(%q) err = %v", c.host, err)
		}
		got, ok := registrableLabel(labels)
		if got != c.label || ok != c.score {
			t.Errorf("registrableLabel(%q) = %q, %v; want %q, %v", c.host, got, ok, c.label, c.score)
		}
	}
}

func TestAssess_UnscoredNamesAreQuietBenign(t *testing.T) {
	l := New()
	for _, h := range []string{"1.1.168.192.in-addr.arpa", "xn--80ak6aa92e.com", "DESKTOP-7H3K2L9.lan", "desktop-ab12cd3", "android-1a2b3c4d5e6f7a8b.local"} {
		a, err := l.Assess(context.Background(), model.Input{Hostname: h})
		if err != nil {
			t.Fatalf("Assess(%q) err = %v", h, err)
		}
		if a.Verdict != schema.VerdictBenign || a.Score != 0 || a.Reasons != nil {
			t.Errorf("Assess(%q) = %+v, want {Benign 0 nil}", h, a)
		}
	}
}
