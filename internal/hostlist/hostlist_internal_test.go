// SPDX-License-Identifier: Apache-2.0

package hostlist

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/obs"
)

func TestParseLine(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantOK   bool
		wantWarn bool // true means reason != ""
	}{
		// silent skips
		{"", "", false, false},
		{"   ", "", false, false},
		{"# comment", "", false, false},
		{"   # indented", "", false, false},
		// happy path
		{"0.0.0.0 example.com", "example.com", true, false},
		{"127.0.0.1 example.com", "example.com", true, false},
		{"0.0.0.0   example.com  ", "example.com", true, false},
		{"0.0.0.0 EXAMPLE.com", "example.com", true, false},
		{"0.0.0.0 example.com.", "example.com", true, false},
		// rejects with WARN
		{"1.2.3.4 example.com", "", false, true},
		{"::1 example.com", "", false, true},
		{"0.0.0.0 a.com b.com", "", false, true},
		// AdGuard ||hostname^ form
		{"||double-click.net^", "double-click.net", true, false},
		{"||example.com^", "example.com", true, false},
		{"||EXAMPLE.com^", "example.com", true, false},
		{"||example.com.^", "example.com", true, false},
		{"||example.com", "", false, true},            // missing trailing ^
		{"||^", "", false, true},                      // empty host
		{"||example..com^", "", false, true},          // invalid host (consecutive dots)
		{"@@||example.com^", "", false, true},         // exception, not supported
		{"||example.com^$important", "", false, true}, // modifier, not supported
		{"||localhost^", "", false, true},             // system alias
		{"||example.com^^", "", false, true},          // double caret (T6 N2)
		{"||", "", false, true},                       // bare double-pipe (T6 N3)
		// AdAway "0 hostname" form
		{"0 example.com", "example.com", true, false},
		{"0   EXAMPLE.com  ", "example.com", true, false},
		{"0 localhost", "", false, true},
		{":: example.com", "", false, true},
		{"0 example.com extra", "", false, true},
		{"0.0.0.0 example..com", "", false, true},
		{"0.0.0.0 -bad.example.com", "", false, true},
		{"0.0.0.0 bad-.example.com", "", false, true},
		{"0.0.0.0 例え.com", "", false, true},
		{"0.0.0.0 localhost", "", false, true},
		{"0.0.0.0 localhost.localdomain", "", false, true},
		{"0.0.0.0 broadcasthost", "", false, true},
	}
	for _, c := range cases {
		gotHost, gotOK, gotReason := parseLine(c.in)
		if gotOK != c.wantOK || gotHost != c.wantHost {
			t.Errorf("parseLine(%q): got (%q, %v), want (%q, %v)", c.in, gotHost, gotOK, c.wantHost, c.wantOK)
		}
		if (gotReason != "") != c.wantWarn {
			t.Errorf("parseLine(%q): got reason=%q, want wantWarn=%v", c.in, gotReason, c.wantWarn)
		}
	}
}

func TestIsSystemAlias(t *testing.T) {
	for _, n := range []string{"localhost", "localhost.localdomain", "broadcasthost"} {
		if !isSystemAlias(n) {
			t.Errorf("isSystemAlias(%q) = false, want true", n)
		}
	}
	for _, n := range []string{"example.com", "broadcast", "localhostx"} {
		if isSystemAlias(n) {
			t.Errorf("isSystemAlias(%q) = true, want false", n)
		}
	}
}

func TestFromEntries_DuplicatesCoalesceToOneEntry(t *testing.T) {
	set, err := FromEntries([]string{"a.test", "A.TEST.", "a.test"})
	if err != nil {
		t.Fatalf("FromEntries: %v", err)
	}
	if got := set.len(); got != 1 {
		t.Errorf("entries = %d; want 1", got)
	}
}

func TestMaxLineSizeBytes_Is1MiB(t *testing.T) {
	if maxLineSizeBytes != 1<<20 {
		t.Fatalf("maxLineSizeBytes = %d; want %d (the error text says 1 MiB)", maxLineSizeBytes, 1<<20)
	}
}

func TestLoad_LineBoundary(t *testing.T) {
	load := func(t *testing.T, longLine string) (Stats, error) {
		t.Helper()
		defer obs.Capture(t)() // the WARN for a skipped line echoes its full content
		path := filepath.Join(t.TempDir(), "list.txt")
		if err := os.WriteFile(path, []byte("0.0.0.0 one.example\n"+longLine+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, stats, err := Load([]Source{{ID: "l1", Path: path}})
		if err != nil {
			return Stats{}, err
		}
		return stats[0], nil
	}
	t.Run("one byte under the limit is read", func(t *testing.T) {
		st, err := load(t, strings.Repeat("a", maxLineSizeBytes-1))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if st.Entries != 1 || st.SkippedLines != 1 {
			t.Fatalf("stats = entries %d skipped %d; want 1/1", st.Entries, st.SkippedLines)
		}
	})
	t.Run("at the limit fails", func(t *testing.T) {
		_, err := load(t, strings.Repeat("a", maxLineSizeBytes))
		if !errors.Is(err, bufio.ErrTooLong) {
			t.Fatalf("Load error = %v; want it to wrap bufio.ErrTooLong", err)
		}
	})
}
