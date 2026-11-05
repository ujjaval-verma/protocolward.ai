// SPDX-License-Identifier: Apache-2.0

package decoy

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/hostlist"
	"protocolward.ai/ward/internal/obs"
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

func TestMaxLineSizeBytes_Is1MiB(t *testing.T) {
	if maxLineSizeBytes != 1<<20 {
		t.Fatalf("maxLineSizeBytes = %d; want %d (the error text says 1 MiB)", maxLineSizeBytes, 1<<20)
	}
}

// loadBody writes body to a temp file and loads it as one decoy source.
func loadBody(t *testing.T, body string) (Stats, error) {
	t.Helper()
	defer obs.Capture(t)()
	path := filepath.Join(t.TempDir(), "decoys.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stats, err := New([]hostlist.Source{{ID: "d1", Path: path}})
	if err != nil {
		return Stats{}, err
	}
	return stats[0], nil
}

func TestNew_LineBoundary(t *testing.T) {
	t.Run("one byte under the limit is read", func(t *testing.T) {
		st, err := loadBody(t, "vault.lan\n"+strings.Repeat("a", maxLineSizeBytes-1)+"\n")
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if st.Entries != 1 || st.SkippedLines != 1 {
			t.Fatalf("stats = entries %d skipped %d; want 1/1", st.Entries, st.SkippedLines)
		}
	})
	t.Run("at the limit fails", func(t *testing.T) {
		_, err := loadBody(t, "vault.lan\n"+strings.Repeat("a", maxLineSizeBytes)+"\n")
		if !errors.Is(err, bufio.ErrTooLong) {
			t.Fatalf("New error = %v; want it to wrap bufio.ErrTooLong", err)
		}
	})
}
