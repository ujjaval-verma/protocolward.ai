// SPDX-License-Identifier: Apache-2.0

package decoy_test

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/decoy"
	"protocolward.ai/ward/internal/hostlist"
	"protocolward.ai/ward/internal/obs"
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

// TestMatch_TrailingDotStripped pins how the dataplane's single fold composes
// with Match: a trailing-dot name folded once with FoldName still hits.
func TestMatch_TrailingDotStripped(t *testing.T) {
	p := writeFile(t, "tripwires.txt", "0.0.0.0 tripwire.dod.test\n")
	set, _, err := decoy.New([]hostlist.Source{{ID: "primary", Path: p}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, ok := set.Match(hostlist.FoldName("tripwire.dod.test.")); !ok {
		t.Error("trailing-dot qname must match")
	}
}

// TestMatch_NeverAllocates pins zero allocations for Match on hits and misses,
// including names that are not folded (Match no longer folds them).
func TestMatch_NeverAllocates(t *testing.T) {
	p := writeFile(t, "tripwires.txt", "0.0.0.0 tripwire.dod.test\n")
	set, _, err := decoy.New([]hostlist.Source{{ID: "primary", Path: p}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, q := range []string{
		"tripwire.dod.test", "tripwire.dod.test.", "TRIPWIRE.dod.test", "NotHere.Unlisted.ORG",
	} {
		if n := testing.AllocsPerRun(100, func() { _, _, _ = set.Match(q) }); n != 0 {
			t.Errorf("Match(%q) allocs = %v, want 0", q, n)
		}
	}
}

// TestMatch_ComparesFoldedNameVerbatim pins that Match does not fold: the
// dataplane folds the query name once and Match compares that name byte for
// byte, so an unfolded name misses. Without this pin a second fold could come
// back unnoticed, because for a lowercase name it costs no allocation.
func TestMatch_ComparesFoldedNameVerbatim(t *testing.T) {
	p := writeFile(t, "tripwires.txt", "0.0.0.0 tripwire.dod.test\n")
	set, _, err := decoy.New([]hostlist.Source{{ID: "primary", Path: p}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, raw := range []string{"TRIPWIRE.dod.test", "tripwire.dod.test."} {
		if _, matched, ok := set.Match(raw); ok {
			t.Errorf("Match(%q) hit %q; an unfolded name must miss", raw, matched)
		}
	}
	_, matched, ok := set.Match(hostlist.FoldName("TRIPWIRE.dod.test."))
	if !ok || matched != "tripwire.dod.test" {
		t.Errorf("Match(FoldName(raw)) = (%q, %v), want (\"tripwire.dod.test\", true)", matched, ok)
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

// TestNew_DuplicateIDs_NotRejected documents that duplicate-id checking moved
// to config.Load; decoy.New no longer re-checks. It is not a feature, and a
// future maintainer may delete it.
func TestNew_DuplicateIDs_NotRejected(t *testing.T) {
	p1 := writeFile(t, "a.txt", "0.0.0.0 alpha.dod.test\n")
	p2 := writeFile(t, "b.txt", "0.0.0.0 beta.dod.test\n")
	set, _, err := decoy.New([]hostlist.Source{
		{ID: "primary", Path: p1},
		{ID: "primary", Path: p2},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, h := range []string{"alpha.dod.test", "beta.dod.test"} {
		if _, _, ok := set.Match(h); !ok {
			t.Errorf("%s must match", h)
		}
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

const invalidSkipMsg = "decoy: skipped invalid hostname"

func invalidSkipWarns(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range obs.Captured(t) {
		if r["level"] == "WARN" && r["msg"] == invalidSkipMsg {
			out = append(out, r)
		}
	}
	return out
}

func TestNew_InvalidNamesSkippedAndWarned(t *testing.T) {
	defer obs.Capture(t)()
	long := strings.Repeat("a", 64) + ".test"
	body := "bad!name.test\n-lead.test\n" + long + "\nok.decoy.test\n"
	path := writeFile(t, "decoys.txt", body)

	set, stats, err := decoy.New([]hostlist.Source{{ID: "d1", Path: path}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if stats[0].Entries != 1 || stats[0].SkippedLines != 3 {
		t.Errorf("stats = entries %d skipped %d; want 1/3", stats[0].Entries, stats[0].SkippedLines)
	}
	if _, _, ok := set.Match("ok.decoy.test"); !ok {
		t.Error("valid name not loaded")
	}
	if _, _, ok := set.Match("bad!name.test"); ok {
		t.Error("invalid name loaded")
	}
	warns := invalidSkipWarns(t)
	if len(warns) != 3 {
		t.Fatalf("WARN count = %d; want 3", len(warns))
	}
	for i, w := range warns {
		if w["source_id"] != "d1" {
			t.Errorf("warn %d source_id = %v", i, w["source_id"])
		}
		if got, want := fmt.Sprint(w["line"]), fmt.Sprint(i+1); got != want {
			t.Errorf("warn %d line = %v; want %v", i, got, want)
		}
		if r, _ := w["reason"].(string); !strings.Contains(r, "failed validation") {
			t.Errorf("warn %d reason = %q", i, r)
		}
	}
}

func TestNew_InvalidNameWarnTruncatesToken(t *testing.T) {
	defer obs.Capture(t)()
	token := strings.Repeat("a!", 3000) + ".test"
	path := writeFile(t, "decoys.txt", token+"\nok.decoy.test\n")

	if _, _, err := decoy.New([]hostlist.Source{{ID: "d1", Path: path}}); err != nil {
		t.Fatalf("New: %v", err)
	}
	warns := invalidSkipWarns(t)
	if len(warns) != 1 {
		t.Fatalf("WARN count = %d; want 1", len(warns))
	}
	r, _ := warns[0]["reason"].(string)
	if len(r) >= 400 {
		t.Errorf("reason is %d bytes; want < 400 (token not truncated)", len(r))
	}
	if strings.Contains(r, token) {
		t.Error("reason contains the full token")
	}
}

func TestNew_OnlyInvalidNames_EmptySourceError(t *testing.T) {
	defer obs.Capture(t)()
	path := writeFile(t, "decoys.txt", "bad!name.test\n-lead.test\n")
	_, _, err := decoy.New([]hostlist.Source{{ID: "d1", Path: path}})
	var ese *decoy.EmptySourceError
	if !errors.As(err, &ese) {
		t.Fatalf("err = %T %v; want *EmptySourceError", err, err)
	}
	if !strings.Contains(err.Error(), "each hostname is valid") {
		t.Errorf("Error() lacks validity remediation: %v", err)
	}
}

func TestNew_InvalidNameWarnsCappedAt16(t *testing.T) {
	defer obs.Capture(t)()
	var b strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&b, "bad!%d.test\n", i)
	}
	b.WriteString("ok.decoy.test\n")
	path := writeFile(t, "decoys.txt", b.String())
	_, stats, err := decoy.New([]hostlist.Source{{ID: "d1", Path: path}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if stats[0].SkippedLines != 20 {
		t.Errorf("SkippedLines = %d; want 20", stats[0].SkippedLines)
	}
	if n := len(invalidSkipWarns(t)); n != 16 {
		t.Errorf("WARN count = %d; want 16", n)
	}
}

func TestNew_SkippedLinesCountsOnlyRejectedLinesWithAReason(t *testing.T) {
	defer obs.Capture(t)()
	body := "vault.lan\n# comment\n  # indented comment\n\nvault.lan # inline\na b c\nbad!name.test\n"
	path := writeFile(t, "decoys.txt", body)

	_, stats, err := decoy.New([]hostlist.Source{{ID: "d1", Path: path}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if stats[0].Entries != 1 || stats[0].SkippedLines != 2 {
		t.Fatalf("stats = entries %d skipped %d; want 1/2", stats[0].Entries, stats[0].SkippedLines)
	}
	warns := invalidSkipWarns(t)
	if len(warns) != 2 {
		t.Fatalf("WARN count = %d; want 2", len(warns))
	}
	if r, _ := warns[0]["reason"].(string); !strings.Contains(r, "got 3 fields") {
		t.Errorf("warn 0 reason = %q; want the field count", r)
	}
	if r, _ := warns[1]["reason"].(string); !strings.Contains(r, "failed validation") {
		t.Errorf("warn 1 reason = %q; want the failed validation", r)
	}
}

func TestNew_OverlongLineErrorsWithLineAndRemediation(t *testing.T) {
	defer obs.Capture(t)()
	body := "one.decoy.test\ntwo.decoy.test\n" + strings.Repeat("a", 1<<20+1) + "\n"
	path := writeFile(t, "decoys.txt", body)

	_, _, err := decoy.New([]hostlist.Source{{ID: "d1", Path: path}})
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("New error = %v; want it to wrap bufio.ErrTooLong", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "line 3") {
		t.Errorf("error %q does not name line 3", msg)
	}
	const marker = " — remediation: "
	i := strings.LastIndex(msg, marker)
	if i < 0 || !strings.Contains(msg[i+len(marker):], "split or remove line 3") {
		t.Errorf("error %q has no remediation naming \"split or remove line 3\"", msg)
	}
}

func TestNew_LongSingleTokenLineIsSkippedNotFatal(t *testing.T) {
	defer obs.Capture(t)()
	body := "vault.lan\n" + strings.Repeat("a", 100<<10) + "\n"
	path := writeFile(t, "decoys.txt", body)

	_, stats, err := decoy.New([]hostlist.Source{{ID: "d1", Path: path}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if stats[0].Entries != 1 || stats[0].SkippedLines != 1 {
		t.Fatalf("stats = entries %d skipped %d; want 1/1", stats[0].Entries, stats[0].SkippedLines)
	}
	if warns := invalidSkipWarns(t); len(warns) != 1 {
		t.Fatalf("WARN count = %d; want 1", len(warns))
	}
}
