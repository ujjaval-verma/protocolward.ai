// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"fmt"
	"testing"

	"protocolward.ai/ward/internal/hostlist"
	"protocolward.ai/ward/internal/policy"
)

var sinkDecision policy.Decision

// BenchmarkDecide measures Engine.Decide over a 1 000-entry allowlist and a
// 100 000-entry blocklist.
func BenchmarkDecide(b *testing.B) {
	allowNames := make([]string, 1_000)
	for i := range allowNames {
		allowNames[i] = fmt.Sprintf("allow%04d.net", i)
	}
	blockNames := make([]string, 100_000)
	for i := range blockNames {
		blockNames[i] = fmt.Sprintf("host%06d.zone%02d.com", i, i%97)
	}
	allow, err := hostlist.FromEntries(allowNames)
	if err != nil {
		b.Fatalf("allow FromEntries: %v", err)
	}
	block, err := hostlist.FromEntries(blockNames)
	if err != nil {
		b.Fatalf("block FromEntries: %v", err)
	}
	engine := policy.NewEngine(allow, block)

	cases := []struct {
		name  string
		query string
		want  policy.Action
	}{
		{"allow_hit", "allow0042.net", policy.ActionAllow},
		{"block_hit", "host000042.zone42.com", policy.ActionBlock},
		{"miss", "nothere.unlisted.org", policy.ActionForward},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			if got := engine.Decide(tc.query).Action; got != tc.want {
				b.Fatalf("Decide(%q).Action = %v, want %v", tc.query, got, tc.want)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				sinkDecision = engine.Decide(tc.query)
			}
		})
	}
}
