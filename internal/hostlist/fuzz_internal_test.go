// SPDX-License-Identifier: Apache-2.0

package hostlist

import (
	"os"
	"path/filepath"
	"strings"
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
