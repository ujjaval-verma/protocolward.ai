// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"fmt"
	"testing"

	"protocolward.ai/ward/internal/hostlist"
	"protocolward.ai/ward/internal/policy"
	"protocolward.ai/ward/pkg/schema"
)

var sinkDecision policy.Decision

// TestDecide_NeverAllocates pins zero allocations for Decide and
// DecideWithVerdict on every path. Decide compares the name verbatim, so
// callers must fold a raw query name with hostlist.FoldName first (the
// dataplane does, once): a raw mixed-case name misses and forwards.
func TestDecide_NeverAllocates(t *testing.T) {
	allow, err := hostlist.FromEntries([]string{"allow0042.net"})
	if err != nil {
		t.Fatalf("allow FromEntries: %v", err)
	}
	block, err := hostlist.FromEntries([]string{"host000042.zone42.com"})
	if err != nil {
		t.Fatalf("block FromEntries: %v", err)
	}
	engine := policy.NewEngine(allow, block)
	cases := []struct {
		name, query string
		want        policy.Action
	}{
		{"allow", "allow0042.net", policy.ActionAllow},
		{"block", "host000042.zone42.com", policy.ActionBlock},
		{"miss", "nothere.unlisted.org", policy.ActionForward},
		{"raw_miss", "NotHere.Unlisted.ORG", policy.ActionForward},
		{"raw_block_name_forwards", "HOST000042.ZONE42.COM", policy.ActionForward},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := engine.Decide(tc.query).Action; got != tc.want {
				t.Errorf("Decide(%q).Action = %v, want %v", tc.query, got, tc.want)
			}
			if got := engine.DecideWithVerdict(tc.query, schema.VerdictBenign).Action; got != tc.want {
				t.Errorf("DecideWithVerdict(%q).Action = %v, want %v", tc.query, got, tc.want)
			}
			if n := testing.AllocsPerRun(100, func() { sinkDecision = engine.Decide(tc.query) }); n != 0 {
				t.Errorf("Decide allocs = %v, want 0", n)
			}
			if n := testing.AllocsPerRun(100, func() {
				sinkDecision = engine.DecideWithVerdict(tc.query, schema.VerdictBenign)
			}); n != 0 {
				t.Errorf("DecideWithVerdict allocs = %v, want 0", n)
			}
		})
	}
}

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
