// SPDX-License-Identifier: Apache-2.0

package hostlist_test

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"protocolward.ai/ward/internal/hostlist"
)

const benchEntries = 100_000

var (
	sinkID      string
	sinkMatched string
	sinkOK      bool
	sinkSet     *hostlist.Set
)

func benchHost(i int) string {
	return fmt.Sprintf("host%06d.zone%02d.com", i, i%97)
}

func benchNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = benchHost(i)
	}
	return names
}

// BenchmarkMatch measures lookups against a 100 000-entry set.
func BenchmarkMatch(b *testing.B) {
	set, err := hostlist.FromEntries(benchNames(benchEntries))
	if err != nil {
		b.Fatalf("FromEntries: %v", err)
	}
	cases := []struct {
		name  string
		query string
		want  bool
	}{
		{"exact_hit", benchHost(42), true},
		{"suffix_hit", "a.b." + benchHost(42), true},
		{"miss", "nothere.unlisted.org", false},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			if _, _, ok := set.Match(tc.query); ok != tc.want {
				b.Fatalf("Match(%q) ok = %v, want %v", tc.query, !tc.want, tc.want)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				sinkID, sinkMatched, sinkOK = set.Match(tc.query)
			}
		})
	}
}

// BenchmarkLoad measures loading one 100 000-line hosts file. B/op is the
// total bytes allocated per load, not the heap retained afterwards.
func BenchmarkLoad(b *testing.B) {
	path := filepath.Join(b.TempDir(), "bench.hosts")
	f, err := os.Create(path)
	if err != nil {
		b.Fatalf("create: %v", err)
	}
	w := bufio.NewWriter(f)
	for i := range benchEntries {
		fmt.Fprintf(w, "0.0.0.0 %s\n", benchHost(i))
	}
	if err := w.Flush(); err != nil {
		b.Fatalf("flush: %v", err)
	}
	if err := f.Close(); err != nil {
		b.Fatalf("close: %v", err)
	}
	sources := []hostlist.Source{{ID: "bench", Path: path}}

	set, stats, err := hostlist.Load(sources)
	if err != nil {
		b.Fatalf("Load: %v", err)
	}
	if len(stats) != 1 || stats[0].Entries != benchEntries {
		b.Fatalf("Load stats = %+v, want one source with %d entries", stats, benchEntries)
	}
	sinkSet = set

	b.ReportAllocs()
	b.ResetTimer()
	var loadErr error
	for range b.N {
		sinkSet, _, loadErr = hostlist.Load(sources)
	}
	if loadErr != nil {
		b.Fatalf("Load: %v", loadErr)
	}
}

// BenchmarkLoadRetained reports the heap a loaded Set retains after a GC
// (retained-B/entry), excluding load-time garbage, at 250k, 1M, 1.5M and 2M
// 22-byte names. Information only. 250k, 1M and 2M fall at the same point of
// the index map's doubling cycle; 1.5M falls between doublings, so the
// per-entry figure moves in steps as the map grows.
func BenchmarkLoadRetained(b *testing.B) {
	for _, size := range []struct {
		name    string
		entries int
	}{
		{"250k", 250_000},
		{"1M", 1_000_000},
		{"1.5M", 1_500_000},
		{"2M", 2_000_000},
	} {
		b.Run(size.name, func(b *testing.B) { benchLoadRetained(b, size.entries) })
	}
}

func benchLoadRetained(b *testing.B, entries int) {
	path := filepath.Join(b.TempDir(), "retained.hosts")
	f, err := os.Create(path)
	if err != nil {
		b.Fatalf("create: %v", err)
	}
	w := bufio.NewWriter(f)
	for i := range entries {
		fmt.Fprintf(w, "0.0.0.0 host%07d.zone%02d.com\n", i, i%97)
	}
	if err := w.Flush(); err != nil {
		b.Fatalf("flush: %v", err)
	}
	if err := f.Close(); err != nil {
		b.Fatalf("close: %v", err)
	}
	sources := []hostlist.Source{{ID: "bench", Path: path}}

	var sum float64
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		b.StartTimer()

		set, stats, loadErr := hostlist.Load(sources)

		b.StopTimer()
		if loadErr != nil {
			b.Fatalf("Load: %v", loadErr)
		}
		if len(stats) != 1 || stats[0].Entries != entries {
			b.Fatalf("Load stats = %+v, want one source with %d entries", stats, entries)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(set)
		delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
		if delta <= 0 {
			b.Fatalf("retained heap delta = %d, want > 0", delta)
		}
		sum += float64(delta)
		b.StartTimer()
	}
	b.ReportMetric(sum/(float64(b.N)*float64(entries)), "retained-B/entry")
}
