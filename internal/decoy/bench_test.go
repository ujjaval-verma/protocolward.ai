// SPDX-License-Identifier: Apache-2.0

package decoy_test

import (
	"fmt"
	"testing"

	"protocolward.ai/ward/internal/decoy"
)

var (
	sinkID      string
	sinkMatched string
	sinkOK      bool
)

// BenchmarkMatch measures lookups against a 1 000-entry decoy set.
func BenchmarkMatch(b *testing.B) {
	names := make([]string, 1_000)
	for i := range names {
		names[i] = fmt.Sprintf("decoy%04d.corp-internal.com", i)
	}
	set, err := decoy.FromEntries(names)
	if err != nil {
		b.Fatalf("FromEntries: %v", err)
	}
	cases := []struct {
		name  string
		query string
		want  bool
	}{
		{"hit", "decoy0042.corp-internal.com", true},
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
