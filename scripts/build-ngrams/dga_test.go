// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestWikiDGAKnownVector(t *testing.T) {
	if got := wikiDGA(2014, 1, 7); got != "intgmxdeadnxuyla" {
		t.Fatalf("wikiDGA(2014-01-07) = %q, want intgmxdeadnxuyla", got)
	}
}

// TestRamnitDGAKnownVector pins the first three names for seed 0x4F2A9C1B,
// matching an independent transcription of the public Ramnit reference
// implementation.
func TestRamnitDGAKnownVector(t *testing.T) {
	want := []string{"kalcepubqekeuaypadb", "stjevxxichqdfnoy", "mkndsqeqgpkw"}
	got := ramnitDGA(0x4F2A9C1B, 3)
	if len(got) != len(want) {
		t.Fatalf("ramnitDGA returned %d names, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ramnitDGA(0x4F2A9C1B, 3)[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
