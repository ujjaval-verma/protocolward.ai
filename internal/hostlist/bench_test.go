// SPDX-License-Identifier: Apache-2.0

package hostlist_test

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
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
	for range b.N {
		sinkSet, _, _ = hostlist.Load(sources)
	}
}
