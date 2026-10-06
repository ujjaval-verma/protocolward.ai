// SPDX-License-Identifier: Apache-2.0

package hostlist_test

import (
	"path/filepath"
	"testing"

	"protocolward.ai/ward/internal/hostlist"
)

func loadSimple(t *testing.T, entries ...string) *hostlist.Set {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	body := ""
	for _, h := range entries {
		body += "0.0.0.0 " + h + "\n"
	}
	mustWrite(t, path, body)
	set, _, err := hostlist.Load([]hostlist.Source{{ID: "t", Path: path}})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return set
}

func TestMatch_Exact(t *testing.T) {
	set := loadSimple(t, "example.com")
	_, matched, ok := set.Match("example.com")
	if !ok {
		t.Fatal("expected hit")
	}
	if matched != "example.com" {
		t.Errorf("matched: got %q, want \"example.com\"", matched)
	}
}

func TestMatch_Suffix_OneLevel(t *testing.T) {
	set := loadSimple(t, "example.com")
	_, matched, ok := set.Match("ads.example.com")
	if !ok {
		t.Fatal("expected hit")
	}
	if matched != "example.com" {
		t.Errorf("matched: got %q, want \"example.com\"", matched)
	}
}

func TestMatch_Suffix_Deep(t *testing.T) {
	set := loadSimple(t, "example.com")
	_, matched, ok := set.Match("a.b.c.example.com")
	if !ok {
		t.Fatal("expected hit")
	}
	if matched != "example.com" {
		t.Errorf("matched: got %q, want \"example.com\"", matched)
	}
}

func TestMatch_NoMatch(t *testing.T) {
	set := loadSimple(t, "example.com")
	if _, _, ok := set.Match("example.org"); ok {
		t.Error("expected miss")
	}
}

func TestMatch_LongestSuffixWins(t *testing.T) {
	set := loadSimple(t, "example.com", "ads.example.com")
	_, matched, ok := set.Match("ads.example.com")
	if !ok {
		t.Fatal("expected hit")
	}
	if matched != "ads.example.com" {
		t.Errorf("matched: got %q, want \"ads.example.com\" (more-specific)", matched)
	}
}

func TestMatch_CaseInsensitive(t *testing.T) {
	set := loadSimple(t, "example.com")
	if _, _, ok := set.Match("ADS.Example.COM"); !ok {
		t.Error("expected case-insensitive hit")
	}
}

func TestMatch_TrailingDot(t *testing.T) {
	set := loadSimple(t, "example.com")
	if _, _, ok := set.Match("ads.example.com."); !ok {
		t.Error("expected trailing-dot tolerance")
	}
}

func TestMatch_SiblingNoBleed(t *testing.T) {
	set := loadSimple(t, "example.com")
	if _, _, ok := set.Match("notexample.com"); ok {
		t.Error("notexample.com must not match example.com (no substring bleed)")
	}
	if _, _, ok := set.Match("sub.example.org"); ok {
		t.Error("sub.example.org must not match example.com")
	}
}

func TestMatch_EmptyQname(t *testing.T) {
	set := loadSimple(t, "example.com")
	if _, _, ok := set.Match(""); ok {
		t.Error("empty qname must not match")
	}
}

func TestMatch_TLDOnly_ExactHit(t *testing.T) {
	set := loadSimple(t, "com")
	_, matched, ok := set.Match("com")
	if !ok {
		t.Fatal("expected hit on TLD-only listing")
	}
	if matched != "com" {
		t.Errorf("matched: got %q, want \"com\"", matched)
	}
}

func TestMatch_TLDOnly_SubdomainHit(t *testing.T) {
	set := loadSimple(t, "com")
	_, matched, ok := set.Match("example.com")
	if !ok {
		t.Fatal("expected subdomain to inherit TLD-only block")
	}
	if matched != "com" {
		t.Errorf("matched: got %q, want \"com\" (TLD is the matching suffix)", matched)
	}
}
