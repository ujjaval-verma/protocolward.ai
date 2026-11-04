// SPDX-License-Identifier: Apache-2.0

package hostlist

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
)

// seedLines returns every line of every file matching the globs, relative to
// the package directory. A glob that matches nothing is fatal, so a moved
// testdata file cannot silently shrink the seed corpus.
func seedLines(f *testing.F, globs ...string) []string {
	f.Helper()
	var lines []string
	for _, g := range globs {
		matches, err := filepath.Glob(g)
		if err != nil {
			f.Fatalf("bad seed glob %q: %v", g, err)
		}
		if len(matches) == 0 {
			f.Fatalf("seed glob %q matched no files", g)
		}
		for _, m := range matches {
			b, err := os.ReadFile(m)
			if err != nil {
				f.Fatalf("read seed %s: %v", m, err)
			}
			lines = append(lines, strings.Split(string(b), "\n")...)
		}
	}
	return lines
}

// FuzzParseLine asserts parseLine never panics, keeps its (hostname, ok,
// reason) contract, and that an accepted hostname is already canonical.
func FuzzParseLine(f *testing.F) {
	for _, l := range seedLines(f,
		"testdata/*.txt",
		"../../testdata/blocklists/trackers-demo.txt",
		"../../testdata/dod/blocklists/*.txt",
		"../../testdata/dod/allowlists/*.txt",
	) {
		f.Add(l)
	}
	for _, l := range []string{"||ads.example.com^", "@@||x.com^", "0 a.com", "127.0.0.1 A.COM.", "", "# c"} {
		f.Add(l)
	}
	f.Fuzz(func(t *testing.T, line string) {
		host, ok, reason := parseLine(line)
		if !ok {
			if host != "" {
				t.Fatalf("parseLine(%q) !ok but hostname %q", line, host)
			}
			return
		}
		if reason != "" || host == "" {
			t.Fatalf("parseLine(%q) ok but hostname=%q reason=%q", line, host, reason)
		}
		if n, nok := NormalizeName(host); !nok || n != host {
			t.Fatalf("parseLine(%q) = %q, NormalizeName gives (%q, %v)", line, host, n, nok)
		}
		if isSystemAlias(host) {
			t.Fatalf("parseLine(%q) accepted system alias %q", line, host)
		}
		h2, ok2, r2 := parseLine("0.0.0.0 " + host)
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

// FuzzHostlistLoad asserts Load accounts for every line of a source: each line
// is loaded, a silent skip (comment or blank), or counted in SkippedLines; a
// source with nothing loadable fails with an EmptySourceError that names a
// remediation; and WARN logs per source never exceed warnCapPerSource. The
// oracle splits lines itself and uses parseLine, not the loader's scanner.
func FuzzHostlistLoad(f *testing.F) {
	for _, g := range []string{
		"testdata/*.txt",
		"../../testdata/blocklists/trackers-demo.txt",
		"../../testdata/dod/blocklists/*.txt",
		"../../testdata/dod/allowlists/*.txt",
	} {
		matches, err := filepath.Glob(g)
		if err != nil {
			f.Fatalf("bad seed glob %q: %v", g, err)
		}
		if len(matches) == 0 {
			f.Fatalf("seed glob %q matched no files", g)
		}
		for _, m := range matches {
			b, err := os.ReadFile(m)
			if err != nil {
				f.Fatalf("read seed %s: %v", m, err)
			}
			f.Add(b)
		}
	}
	bad := strings.Repeat("||bad!^\n", 20)
	for _, s := range []string{
		"",
		"# only a comment\n",
		"0.0.0.0 a.com\r\n0.0.0.0 a.com\n||bad!^\n",
		bad,
		bad + "0.0.0.0 ok.example\n",
	} {
		f.Add([]byte(s))
	}

	warns := installWarnCounter(f, "hostlist: skipped unparsable line")
	path := filepath.Join(f.TempDir(), "source.txt")
	var seq atomic.Uint64

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip("input over 64 KiB")
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
		wantSkipped := 0
		for _, l := range lines {
			l = strings.TrimSuffix(l, "\r")
			host, ok, reason := parseLine(l)
			switch {
			case ok:
				want[host] = struct{}{}
			case reason != "":
				wantSkipped++
			}
		}

		set, stats, err := Load([]Source{{ID: id, Path: path}})
		gotWarns := warns.take(id)
		if wantWarns := min(wantSkipped, warnCapPerSource); gotWarns != wantWarns {
			t.Fatalf("WARN count = %d, want %d (skipped lines %d, cap %d)", gotWarns, wantWarns, wantSkipped, warnCapPerSource)
		}

		if len(want) == 0 {
			var ee *EmptySourceError
			if !errors.As(err, &ee) {
				t.Fatalf("no loadable line: Load error = %T %v, want *EmptySourceError", err, err)
			}
			const marker = " — remediation: "
			msg := err.Error()
			if i := strings.LastIndex(msg, marker); i < 0 || strings.TrimSpace(msg[i+len(marker):]) == "" {
				t.Fatalf("EmptySourceError names no remediation after %q: %q", marker, msg)
			}
			return
		}
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(stats) != 1 || stats[0].ID != id {
			t.Fatalf("stats = %+v, want one entry for %q", stats, id)
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
