// SPDX-License-Identifier: Apache-2.0

package decoy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"protocolward.ai/ward/internal/hostlist"
)

// FuzzDecoyParseLine asserts parseLine never panics, keeps its (host, ok,
// reason) contract, and that an accepted host is already canonical.
func FuzzDecoyParseLine(f *testing.F) {
	matches, err := filepath.Glob("../../testdata/dod/decoys/*.txt")
	if err != nil {
		f.Fatalf("bad seed glob: %v", err)
	}
	if len(matches) == 0 {
		f.Fatal("seed glob ../../testdata/dod/decoys/*.txt matched no files")
	}
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			f.Fatalf("read seed %s: %v", m, err)
		}
		for _, l := range strings.Split(string(b), "\n") {
			f.Add(l)
		}
	}
	for _, l := range []string{"vault.lan", "0.0.0.0 vault.lan", "vault.lan # note", "a b c", "bad!name.test", "", "#x"} {
		f.Add(l)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		host, ok, reason := parseLine(raw)
		if !ok {
			if host != "" {
				t.Fatalf("parseLine(%q) !ok but host %q", raw, host)
			}
			return
		}
		if reason != "" || host == "" {
			t.Fatalf("parseLine(%q) ok but host=%q reason=%q", raw, host, reason)
		}
		if n, nok := hostlist.NormalizeName(host); !nok || n != host {
			t.Fatalf("parseLine(%q) = %q, NormalizeName gives (%q, %v)", raw, host, n, nok)
		}
		h2, ok2, r2 := parseLine(host)
		if h2 != host || !ok2 || r2 != "" {
			t.Fatalf("re-parse of %q = (%q, %v, %q), want (%q, true, \"\")", host, h2, ok2, r2, host)
		}
	})
}

// warnCounter is a slog.Handler that counts records with one message, keyed by
// their source_id attribute. take returns and clears one id's count, so the
// map does not grow while fuzzing.
type warnCounter struct {
	msg    string
	mu     sync.Mutex
	counts map[string]int
}

func (h *warnCounter) Enabled(context.Context, slog.Level) bool { return true }

func (h *warnCounter) Handle(_ context.Context, r slog.Record) error {
	if r.Message != h.msg {
		return nil
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "source_id" {
			h.mu.Lock()
			h.counts[a.Value.String()]++
			h.mu.Unlock()
			return false
		}
		return true
	})
	return nil
}

func (h *warnCounter) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *warnCounter) WithGroup(string) slog.Handler      { return h }

func (h *warnCounter) take(id string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := h.counts[id]
	delete(h.counts, id)
	return n
}

// installWarnCounter makes a warnCounter the default logger for the target and
// restores the previous slog default, log output and log flags on cleanup.
// With the built-in default handler slog.SetDefault redirects the log package,
// so restoring the slog default alone would not undo it.
func installWarnCounter(f *testing.F, msg string) *warnCounter {
	f.Helper()
	h := &warnCounter{msg: msg, counts: map[string]int{}}
	prev := slog.Default()
	prevWriter, prevFlags := log.Writer(), log.Flags()
	slog.SetDefault(slog.New(h))
	f.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})
	return h
}

// FuzzDecoyNew asserts New accounts for every non-blank line of a source: each
// is accepted or counted in SkippedLines (comments included, as the loader
// does today); a source with nothing loadable fails with an EmptySourceError
// that names a remediation; and invalid-name WARN logs per source never exceed
// warnCapPerSource. The oracle splits lines itself and uses parseLine.
func FuzzDecoyNew(f *testing.F) {
	matches, err := filepath.Glob("../../testdata/dod/decoys/*.txt")
	if err != nil {
		f.Fatalf("bad seed glob: %v", err)
	}
	if len(matches) == 0 {
		f.Fatal("seed glob ../../testdata/dod/decoys/*.txt matched no files")
	}
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			f.Fatalf("read seed %s: %v", m, err)
		}
		f.Add(b)
	}
	bad := strings.Repeat("bad!name.test\n", 20)
	for _, s := range []string{
		"",
		"vault.lan\nvault.lan\n# c\n a b c \n",
		"vault.lan\r\nbad!name.test\r\n",
		bad,
		bad + "vault.lan\n",
	} {
		f.Add([]byte(s))
	}

	warns := installWarnCounter(f, "decoy: skipped invalid hostname")
	path := filepath.Join(f.TempDir(), "source.txt")
	var seq atomic.Uint64

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 32<<10 {
			t.Skip("input over 32 KiB")
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprintf("fuzz-%d", seq.Add(1))

		lines := strings.Split(string(data), "\n")
		if lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		want := map[string]struct{}{}
		var acceptedLines, nonBlankLines, wantSkipped, wantWarn int
		for _, raw := range lines {
			raw = strings.TrimSuffix(raw, "\r")
			host, ok, reason := parseLine(raw)
			blank := strings.TrimSpace(raw) == ""
			if !blank {
				nonBlankLines++
			}
			switch {
			case ok:
				acceptedLines++
				want[host] = struct{}{}
			case !blank:
				wantSkipped++
				if reason != "" {
					wantWarn++
				}
			}
		}

		set, stats, err := New([]hostlist.Source{{ID: id, Path: path}})
		gotWarns := warns.take(id)
		if wantWarns := min(wantWarn, warnCapPerSource); gotWarns != wantWarns {
			t.Fatalf("WARN count = %d, want %d (invalid names %d, cap %d)", gotWarns, wantWarns, wantWarn, warnCapPerSource)
		}

		if len(want) == 0 {
			var ee *EmptySourceError
			if !errors.As(err, &ee) {
				t.Fatalf("no loadable line: New error = %T %v, want *EmptySourceError", err, err)
			}
			const marker = " — remediation: "
			msg := err.Error()
			if i := strings.LastIndex(msg, marker); i < 0 || strings.TrimSpace(msg[i+len(marker):]) == "" {
				t.Fatalf("EmptySourceError names no remediation after %q: %q", marker, msg)
			}
			return
		}
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if len(stats) != 1 || stats[0].ID != id {
			t.Fatalf("stats = %+v, want one entry for %q", stats, id)
		}
		if acceptedLines+stats[0].SkippedLines != nonBlankLines {
			t.Fatalf("accepted %d + SkippedLines %d != non-blank lines %d", acceptedLines, stats[0].SkippedLines, nonBlankLines)
		}
		if stats[0].SkippedLines != wantSkipped {
			t.Fatalf("SkippedLines = %d, want %d", stats[0].SkippedLines, wantSkipped)
		}
		if stats[0].Entries != len(want) {
			t.Fatalf("Entries = %d, want %d", stats[0].Entries, len(want))
		}
		for host := range want {
			if gotID, matched, ok := set.Match(host); !ok || gotID != id || matched != host {
				t.Fatalf("Match(%q) = (%q, %q, %v), want (%q, %q, true)", host, gotID, matched, ok, id, host)
			}
		}
	})
}
