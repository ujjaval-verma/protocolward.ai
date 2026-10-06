// SPDX-License-Identifier: Apache-2.0

package allowlist_test

import (
	"os"
	"path/filepath"
	"testing"

	"protocolward.ai/ward/internal/allowlist"
)

func TestLoad_DelegatesToHostlist(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "overrides.txt")
	if err := os.WriteFile(p, []byte("0.0.0.0 foo.example.com\n0.0.0.0 bar.example.com\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	set, stats, err := allowlist.Load([]allowlist.Source{{ID: "my", Path: p}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(stats) != 1 || stats[0].Entries != 2 {
		t.Fatalf("stats: %+v", stats)
	}
	if id, matched, ok := set.Match("sub.foo.example.com"); !ok || id != "my" || matched != "foo.example.com" {
		t.Errorf("Match: id=%q matched=%q ok=%v", id, matched, ok)
	}
}
