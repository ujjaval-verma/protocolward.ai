// SPDX-License-Identifier: Apache-2.0

package decoy

import (
	"strings"
	"testing"
)

func TestParseLine_ReasonContract(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantReason string // substring; "" means the reason must be empty
	}{
		{"three fields", "a b c", "got 3 fields"},
		{"four fields with inline comment", "a b c d # x", "got 4 fields"},
		{"comment", "# x", ""},
		{"indented comment", "  # x", ""},
		{"blank", "", ""},
		{"whitespace only", " \t ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, ok, reason := parseLine(tc.raw)
			if ok || host != "" {
				t.Fatalf("parseLine(%q) = (%q, %v, _); want rejected", tc.raw, host, ok)
			}
			if tc.wantReason == "" {
				if reason != "" {
					t.Fatalf("parseLine(%q) reason = %q; want empty", tc.raw, reason)
				}
				return
			}
			if !strings.Contains(reason, tc.wantReason) {
				t.Fatalf("parseLine(%q) reason = %q; want it to contain %q", tc.raw, reason, tc.wantReason)
			}
		})
	}
}
