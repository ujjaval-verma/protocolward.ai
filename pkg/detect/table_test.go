// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"bytes"
	"testing"
)

func TestParseTable_EmbeddedIsValid(t *testing.T) {
	l, err := parseTable(ngramsBin)
	if err != nil {
		t.Fatalf("parseTable(embedded) err = %v", err)
	}
	if l.v != 38 {
		t.Errorf("alphabet size = %d, want 38", l.v)
	}
	if got, want := len(l.table), 38*38*38; got != want {
		t.Errorf("len(table) = %d, want %d", got, want)
	}
	if len(ngramsBin) > 200*1024 {
		t.Errorf("ngrams.bin is %d bytes, spec budget is < 200 KB", len(ngramsBin))
	}
}

func TestParseTable_RejectsMalformed(t *testing.T) {
	good := append([]byte(nil), ngramsBin...)
	mut := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	// synth builds a length-consistent table with v symbols: '^' first, then
	// distinct bytes from 0x01 upward.
	synth := func(v int) []byte {
		b := append([]byte("PWNG"), 1, 8, byte(v), '^')
		for i := 1; i < v; i++ {
			b = append(b, byte(i))
		}
		return append(b, make([]byte, v*v*v)...)
	}
	cases := map[string][]byte{
		"v=1":              synth(1),
		"v=65":             synth(65),
		"missing 'z'":      mut(func(b []byte) []byte { b[7+26] = '_'; return b }),
		"empty":            nil,
		"bad magic":        mut(func(b []byte) []byte { b[0] = 'X'; return b }),
		"version 2":        mut(func(b []byte) []byte { b[4] = 2; return b }),
		"zero scale":       mut(func(b []byte) []byte { b[5] = 0; return b }),
		"truncated":        good[:len(good)-1],
		"trailing byte":    append(append([]byte(nil), good...), 0),
		"boundary not '^'": mut(func(b []byte) []byte { b[7], b[8] = b[8], b[7]; return b }),
		"duplicate symbol": mut(func(b []byte) []byte { b[8] = 'b'; return b }),
		"header only":      good[:7],
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTable(b); err == nil {
				t.Errorf("parseTable(%s) err = nil, want error", name)
			}
		})
	}
	if !bytes.Equal(good, ngramsBin) {
		t.Fatal("test mutated the embedded table")
	}
}

func TestMeanNLL_NaturalBelowRandom(t *testing.T) {
	l := New()
	natural := []string{"google", "wikipedia", "facebook", "weather", "printer"}
	random := []string{"qwkjxzpvtr", "xkqzjvbw", "8094deb269cb149e"}
	for _, n := range natural {
		if got := l.meanNLL(n); got >= 4.0 {
			t.Errorf("meanNLL(%q) = %.2f, want < 4.0 bits", n, got)
		}
	}
	for _, r := range random {
		if got := l.meanNLL(r); got <= 6.0 {
			t.Errorf("meanNLL(%q) = %.2f, want > 6.0 bits", r, got)
		}
	}
}

func TestMeanNLL_UnderscoreLooksUpAsHyphen(t *testing.T) {
	l := New()
	if a, b := l.meanNLL("_dmarc"), l.meanNLL("-dmarc"); a != b {
		t.Errorf("meanNLL(_dmarc) = %v, meanNLL(-dmarc) = %v; want equal", a, b)
	}
}
