// SPDX-License-Identifier: Apache-2.0

package decoy

import "testing"

func TestFromEntries_DuplicatesCoalesceToOneEntry(t *testing.T) {
	set, err := FromEntries([]string{"a.lan", "A.LAN.", "a.lan"})
	if err != nil {
		t.Fatalf("FromEntries: %v", err)
	}
	if got := len(set.entries); got != 1 {
		t.Errorf("entries = %d; want 1", got)
	}
}
