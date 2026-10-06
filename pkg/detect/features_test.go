// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"math"
	"testing"
)

func TestMeasure(t *testing.T) {
	cases := []struct {
		label     string
		length    int
		entropy   float64
		digit     float64
		consonant int
	}{
		{"aaaa", 4, 0, 0, 0},
		{"abcd", 4, 2, 0, 3},
		{"a1b2", 4, 2, 0.5, 1},
		{"4399", 4, 1.5, 1, 0},
		{"strengths", 9, 2.7255, 0, 5},
		{"rhythm", 6, 2.2516, 0, 3}, // y counts as a vowel
		{"bc-df_gh", 8, 3, 0, 2},    // '-' and '_' break runs
		{"x", 1, 0, 0, 1},
	}
	l := New()
	for _, c := range cases {
		f := l.measure(c.label)
		if f.length != c.length {
			t.Errorf("measure(%q).length = %d, want %d", c.label, f.length, c.length)
		}
		if math.Abs(f.entropy-c.entropy) > 1e-3 {
			t.Errorf("measure(%q).entropy = %.4f, want %.4f", c.label, f.entropy, c.entropy)
		}
		if math.Abs(f.digit-c.digit) > 1e-9 {
			t.Errorf("measure(%q).digit = %.3f, want %.3f", c.label, f.digit, c.digit)
		}
		if f.consonant != c.consonant {
			t.Errorf("measure(%q).consonant = %d, want %d", c.label, f.consonant, c.consonant)
		}
		if f.meanNLL <= 0 {
			t.Errorf("measure(%q).meanNLL = %.3f, want > 0", c.label, f.meanNLL)
		}
	}
}
