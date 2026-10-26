// SPDX-License-Identifier: Apache-2.0

package decoy

import (
	"os"
	"path/filepath"
	"strings"
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
