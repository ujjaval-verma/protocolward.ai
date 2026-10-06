// SPDX-License-Identifier: Apache-2.0

package decoy_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"protocolward.ai/ward/internal/decoy"
	"protocolward.ai/ward/internal/hostlist"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestNew_EmptySources_NoOp(t *testing.T) {
	set, stats, err := decoy.New(nil)
	if err != nil {
		t.Fatalf("New(nil): %v", err)
	}
	if set == nil {
		t.Fatal("expected non-nil empty *Set")
	}
	if len(stats) != 0 {
		t.Errorf("stats: got %d entries, want 0", len(stats))
	}
	if _, _, ok := set.Match("anything.test"); ok {
		t.Error("empty set must not match")
	}
}

func TestNew_Happy_ExactMatch(t *testing.T) {
	p := writeFile(t, "tripwires.txt", "# decoy file\n0.0.0.0 tripwire.dod.test\n0.0.0.0 vault.internal.acme\n")
	set, stats, err := decoy.New([]hostlist.Source{{ID: "primary", Path: p}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("stats: got %d entries, want 1", len(stats))
	}
	if stats[0].Entries != 2 {
		t.Errorf("entries: got %d, want 2", stats[0].Entries)
	}

	id, matched, ok := set.Match("tripwire.dod.test")
	if !ok {
		t.Fatal("expected match for tripwire.dod.test")
	}
	if id != "primary" {
		t.Errorf("decoyID: got %q want %q", id, "primary")
	}
	if matched != "tripwire.dod.test" {
		t.Errorf("matched: got %q want %q", matched, "tripwire.dod.test")
	}
}

func TestMatch_ExactOnly_SubdomainMisses(t *testing.T) {
	// Decoy honeytokens are point-targets: a planted tripwire.dod.test must NOT
	// match scanner.tripwire.dod.test. This is the semantic difference from
	// hostlist.Set, which does longest-suffix matching.
	p := writeFile(t, "tripwires.txt", "0.0.0.0 tripwire.dod.test\n")
	set, _, err := decoy.New([]hostlist.Source{{ID: "primary", Path: p}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, ok := set.Match("scanner.tripwire.dod.test"); ok {
		t.Error("subdomain of a decoy must NOT match (exact-match-only semantic)")
	}
	if _, _, ok := set.Match("a.scanner.tripwire.dod.test"); ok {
		t.Error("deeper subdomain must NOT match")
	}
}

func TestMatch_NormalizesCase(t *testing.T) {
	p := writeFile(t, "tripwires.txt", "0.0.0.0 Tripwire.DOD.Test\n")
	set, _, err := decoy.New([]hostlist.Source{{ID: "primary", Path: p}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, ok := set.Match("tripwire.dod.test"); !ok {
		t.Error("lowercase query must match an upper-case-loaded decoy")
	}
}

func TestMatch_TrailingDotStripped(t *testing.T) {
	p := writeFile(t, "tripwires.txt", "0.0.0.0 tripwire.dod.test\n")
	set, _, err := decoy.New([]hostlist.Source{{ID: "primary", Path: p}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, ok := set.Match("tripwire.dod.test."); !ok {
		t.Error("trailing-dot qname must match")
	}
}

func TestMatch_Miss(t *testing.T) {
	p := writeFile(t, "tripwires.txt", "0.0.0.0 tripwire.dod.test\n")
	set, _, err := decoy.New([]hostlist.Source{{ID: "primary", Path: p}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, ok := set.Match("unrelated.example.com"); ok {
		t.Error("unrelated host must NOT match")
	}
}

func TestNew_MissingFile_TypedError(t *testing.T) {
	_, _, err := decoy.New([]hostlist.Source{{ID: "primary", Path: "/nonexistent/decoys.txt"}})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	var mse *decoy.MissingSourceError
	if !errors.As(err, &mse) {
		t.Errorf("expected *decoy.MissingSourceError, got %T: %v", err, err)
	}
}

func TestNew_DuplicateID_Errors(t *testing.T) {
	p1 := writeFile(t, "a.txt", "0.0.0.0 alpha.dod.test\n")
	p2 := writeFile(t, "b.txt", "0.0.0.0 beta.dod.test\n")
	_, _, err := decoy.New([]hostlist.Source{
		{ID: "primary", Path: p1},
		{ID: "primary", Path: p2},
	})
	if err == nil {
		t.Fatal("expected duplicate-id error")
	}
	var dup *decoy.DuplicateIDError
	if !errors.As(err, &dup) {
		t.Errorf("expected *decoy.DuplicateIDError, got %T: %v", err, err)
	}
}

func TestNew_EmptySource_Errors(t *testing.T) {
	p := writeFile(t, "empty.txt", "# nothing parseable\n# just comments\n")
	_, _, err := decoy.New([]hostlist.Source{{ID: "primary", Path: p}})
	if err == nil {
		t.Fatal("expected empty-source error")
	}
	var ese *decoy.EmptySourceError
	if !errors.As(err, &ese) {
		t.Errorf("expected *decoy.EmptySourceError, got %T: %v", err, err)
	}
}
