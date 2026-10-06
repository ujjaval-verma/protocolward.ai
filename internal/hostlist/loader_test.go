// SPDX-License-Identifier: Apache-2.0

package hostlist_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"protocolward.ai/ward/internal/hostlist"
	"protocolward.ai/ward/internal/obs"
)

func TestLoad_Simple(t *testing.T) {
	set, stats, err := hostlist.Load([]hostlist.Source{
		{ID: "simple", Path: "testdata/hosts-simple.txt"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("stats len: got %d, want 1", len(stats))
	}
	if stats[0].Entries != 3 || stats[0].SkippedLines != 0 {
		t.Errorf("stats[0]: got entries=%d skipped=%d, want 3/0", stats[0].Entries, stats[0].SkippedLines)
	}
	if _, _, ok := set.Match("ads.example.com"); !ok {
		t.Errorf("expected Match(ads.example.com) to hit")
	}
}

func TestLoad_Mixed(t *testing.T) {
	defer obs.Capture(t)()
	_, stats, err := hostlist.Load([]hostlist.Source{
		{ID: "mixed", Path: "testdata/hosts-mixed.txt"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats[0].Entries != 3 {
		t.Errorf("entries: got %d, want 3", stats[0].Entries)
	}
	if stats[0].SkippedLines != 3 {
		t.Errorf("skipped: got %d, want 3", stats[0].SkippedLines)
	}
	warns := filterRecords(t, func(r map[string]any) bool {
		return r["level"] == "WARN" && r["msg"] == "hostlist: skipped unparsable line"
	})
	if len(warns) != 3 {
		t.Errorf("WARN count: got %d, want 3", len(warns))
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, _, err := hostlist.Load([]hostlist.Source{
		{ID: "missing", Path: filepath.Join(t.TempDir(), "nope.txt")},
	})
	var mse *hostlist.MissingSourceError
	if !errors.As(err, &mse) {
		t.Fatalf("expected MissingSourceError, got %T: %v", err, err)
	}
}

func TestLoad_EmptySource(t *testing.T) {
	_, _, err := hostlist.Load([]hostlist.Source{
		{ID: "empty", Path: "testdata/hosts-empty.txt"},
	})
	var ese *hostlist.EmptySourceError
	if !errors.As(err, &ese) {
		t.Fatalf("expected EmptySourceError, got %T: %v", err, err)
	}
}

func TestLoad_DuplicateID(t *testing.T) {
	_, _, err := hostlist.Load([]hostlist.Source{
		{ID: "dup", Path: "testdata/hosts-simple.txt"},
		{ID: "dup", Path: "testdata/hosts-simple.txt"},
	})
	var de *hostlist.DuplicateIDError
	if !errors.As(err, &de) {
		t.Fatalf("expected DuplicateIDError, got %T: %v", err, err)
	}
}

func TestLoad_WARNCappedAt16(t *testing.T) {
	defer obs.Capture(t)()
	_, _, err := hostlist.Load([]hostlist.Source{
		{ID: "flood", Path: "testdata/hosts-flooded.txt"},
	})
	var ese *hostlist.EmptySourceError
	if !errors.As(err, &ese) {
		t.Fatalf("expected EmptySourceError, got %T: %v", err, err)
	}
	warns := filterRecords(t, func(r map[string]any) bool {
		return r["level"] == "WARN" && r["msg"] == "hostlist: skipped unparsable line"
	})
	if len(warns) != 16 {
		t.Errorf("WARN cap: got %d lines, want 16", len(warns))
	}
}

func TestLoad_MatchEmptyString_NoHit(t *testing.T) {
	set, _, err := hostlist.Load([]hostlist.Source{
		{ID: "simple", Path: "testdata/hosts-simple.txt"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, _, ok := set.Match(""); ok {
		t.Errorf("Match(\"\") returned a hit, expected (empty, empty, false)")
	}
}

func TestLoad_DuplicateHostnameAcrossSources(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	mustWrite(t, a, "0.0.0.0 ads.example.com\n")
	mustWrite(t, b, "0.0.0.0 ads.example.com\n")
	set, _, err := hostlist.Load([]hostlist.Source{
		{ID: "first", Path: a},
		{ID: "second", Path: b},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	listID, _, ok := set.Match("ads.example.com")
	if !ok {
		t.Fatal("expected hit")
	}
	if listID != "second" {
		t.Errorf("listID: got %q, want \"second\" (later source wins)", listID)
	}

	// Verify the INFO log was emitted.
	records := obs.Captured(t)
	var dupLogged int
	for _, r := range records {
		if r["msg"] == "hostlist: hostname appears in multiple sources" {
			dupLogged++
			if got, _ := r["hostname"].(string); got != "ads.example.com" {
				t.Errorf("hostname field: got %q, want \"ads.example.com\"", got)
			}
			if got, _ := r["previous_list_id"].(string); got != "first" {
				t.Errorf("previous_list_id: got %q, want \"first\"", got)
			}
			if got, _ := r["new_list_id"].(string); got != "second" {
				t.Errorf("new_list_id: got %q, want \"second\"", got)
			}
		}
	}
	if dupLogged != 1 {
		t.Errorf("expected exactly 1 cross-source duplicate INFO log, got %d", dupLogged)
	}
}

func TestLoad_IntraSourceDuplicatesNotDoubleCounted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	// Same hostname twice in one source.
	mustWrite(t, path, "0.0.0.0 example.com\n0.0.0.0 example.com\n")
	_, stats, err := hostlist.Load([]hostlist.Source{{ID: "dups", Path: path}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats[0].Entries != 1 {
		t.Errorf("Entries: got %d, want 1 (duplicates within a source must not double-count)", stats[0].Entries)
	}
}

// filterRecords returns all captured log records for which predicate returns true.
func filterRecords(t *testing.T, predicate func(map[string]any) bool) []map[string]any {
	t.Helper()
	var matched []map[string]any
	for _, r := range obs.Captured(t) {
		if predicate(r) {
			matched = append(matched, r)
		}
	}
	return matched
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
