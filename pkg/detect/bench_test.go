// SPDX-License-Identifier: Apache-2.0

package detect_test

import (
	"context"
	"testing"

	"protocolward.ai/ward/pkg/detect"
	"protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

var sinkAssessment schema.Assessment

// BenchmarkAssess measures the lexical detector on a benign name, a DGA-like
// name and a maximum-length (63-byte) random-looking label.
func BenchmarkAssess(b *testing.B) {
	l := detect.New()
	ctx := context.Background()
	longLabel := "qzxjvkwpmbtrnhgdlsfycaueioqzxjvkwpmbtrnhgdlsfycaueioqzxjvkwpmbt" + ".com"

	cases := []struct {
		name  string
		host  string
		check func(a schema.Assessment) bool
		want  string
	}{
		{"benign", "www.google.com", func(a schema.Assessment) bool { return a.Verdict == schema.VerdictBenign }, "Verdict == VerdictBenign"},
		{"dga_like", "qwkjxzpvtr.net", func(a schema.Assessment) bool { return a.Verdict == schema.VerdictMalicious }, "Verdict == VerdictMalicious"},
		{"long_label", longLabel, func(a schema.Assessment) bool { return a.Score > 0 }, "Score > 0"},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			in := model.Input{Hostname: tc.host}
			a, err := l.Assess(ctx, in)
			if err != nil {
				b.Fatalf("Assess(%q): %v", tc.host, err)
			}
			if !tc.check(a) {
				b.Fatalf("Assess(%q) = %+v, want %s", tc.host, a, tc.want)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				sinkAssessment, _ = l.Assess(ctx, in)
			}
		})
	}
}
