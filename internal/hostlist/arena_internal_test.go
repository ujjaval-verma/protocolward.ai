// SPDX-License-Identifier: Apache-2.0

package hostlist

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/obs"
)

const multiSourceMsg = "hostlist: hostname appears in multiple sources"

func constHash(string) uint64 { return 1 }

func writeHosts(t *testing.T, dir, name string, hosts []string) string {
	t.Helper()
	var b strings.Builder
	for _, h := range hosts {
		b.WriteString("0.0.0.0 " + h + "\n")
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func countInfo(t *testing.T) int {
	t.Helper()
	n := 0
	for _, r := range obs.Captured(t) {
		if r["level"] == "INFO" && r["msg"] == multiSourceMsg {
			n++
		}
	}
	return n
}

type statKey struct {
	ID, Path         string
	Entries, Skipped int
}

func keys(stats []Stats) []statKey {
	out := make([]statKey, len(stats))
	for i, s := range stats {
		out[i] = statKey{s.ID, s.Path, s.Entries, s.SkippedLines}
	}
	return out
}

func TestForcedHashCollisions_MatchesRealHash(t *testing.T) {
	dir := t.TempDir()
	a := make([]string, 0, 32)
	b := make([]string, 0, 32)
	for i := range 30 {
		a = append(a, fmt.Sprintf("a%02d.example.com", i))
	}
	a = append(a, "a00.example.com", "a01.example.com") // in-source duplicates
	for i := 20; i < 50; i++ {                          // 20..29 overlap with a
		b = append(b, fmt.Sprintf("a%02d.example.com", i))
	}
	b = append(b, "a45.example.com", "zz.other.net")
	pa, pb := writeHosts(t, dir, "a.txt", a), writeHosts(t, dir, "b.txt", b)
	srcs := []Source{{ID: "A", Path: pa}, {ID: "B", Path: pb}}

	restore := obs.Capture(t)
	realSet, realStats, err := Load(srcs)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	realInfo := countInfo(t)
	restore()

	defer obs.Capture(t)()
	forced := newSet([]string{"A", "B"}, constHash)
	forcedStats, err := forced.load(srcs)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := countInfo(t); got != realInfo || got != 10 {
		t.Errorf("Info logs forced=%d real=%d, want 10 both", got, realInfo)
	}
	rk, fk := keys(realStats), keys(forcedStats)
	for i := range rk {
		if rk[i] != fk[i] {
			t.Errorf("stats[%d] forced=%+v real=%+v", i, fk[i], rk[i])
		}
	}
	if forced.len() != realSet.len() || forced.len() != 51 {
		t.Errorf("len forced=%d real=%d, want 51", forced.len(), realSet.len())
	}
	for _, h := range append(append([]string{}, a...), b...) {
		wantID, wantM, wantOK := realSet.Match(h)
		gotID, gotM, gotOK := forced.Match("x." + h)
		if !wantOK || !gotOK || gotID != wantID || gotM != h || wantM != h {
			t.Errorf("%s: forced=(%q,%q,%v) real=(%q,%q,%v)", h, gotID, gotM, gotOK, wantID, wantM, wantOK)
		}
	}
	if id, _, _ := forced.Match("a25.example.com"); id != "B" {
		t.Errorf("cross-source winner = %q, want B", id)
	}
	for _, miss := range []string{"example.com", "a99.example.com", "other.net", "unlisted.org"} {
		if _, _, ok := forced.Match(miss); ok {
			t.Errorf("Match(%q) hit, want miss", miss)
		}
	}
}

func TestFromEntries_ForcedHash(t *testing.T) {
	names := []string{"a.test", "b.test", "c.d.test", "A.TEST."}
	set, err := fromEntries(names, constHash)
	if err != nil {
		t.Fatal(err)
	}
	if set.len() != 3 {
		t.Errorf("len = %d, want 3", set.len())
	}
	for _, n := range []string{"a.test", "b.test", "x.c.d.test"} {
		if id, _, ok := set.Match(n); !ok || id != InlineSourceID {
			t.Errorf("Match(%q) = (%q, %v)", n, id, ok)
		}
	}
	if _, _, ok := set.Match("d.test"); ok {
		t.Error("d.test should miss")
	}
}

func TestLongNameOverflow(t *testing.T) {
	label := strings.Repeat("a", 63)
	long := strings.Join([]string{label, label, label, label}, ".") // 255 bytes
	longer := "x." + long                                           // 257 bytes
	if len(long) < 255 || len(longer) < 256 {
		t.Fatalf("bad fixture lengths %d %d", len(long), len(longer))
	}
	dir := t.TempDir()
	p := writeHosts(t, dir, "l.txt", []string{longer, "short.test"})
	for name, set := range map[string]func() (*Set, error){
		"real": func() (*Set, error) { s, _, err := Load([]Source{{ID: "L", Path: p}}); return s, err },
		"forced": func() (*Set, error) {
			s := newSet([]string{"L"}, constHash)
			_, err := s.load([]Source{{ID: "L", Path: p}})
			return s, err
		},
	} {
		s, err := set()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if id, m, ok := s.Match(longer); !ok || id != "L" || m != longer {
			t.Errorf("%s exact: (%q,%q,%v)", name, id, m, ok)
		}
		if _, m, ok := s.Match("q." + longer); !ok || m != longer {
			t.Errorf("%s suffix: (%q,%v)", name, m, ok)
		}
		if _, _, ok := s.Match(long); ok {
			t.Errorf("%s: parent of long name should miss", name)
		}
		if _, _, ok := s.Match("short.test"); !ok {
			t.Errorf("%s: short.test should hit", name)
		}
		if s.len() != 2 {
			t.Errorf("%s: len = %d, want 2", name, s.len())
		}
	}
}

// crossCases: A, B, C file contents and expectations.
var crossCases = []struct {
	name    string
	files   [][]string
	entries []int
	winner  string
	infos   int
}{
	{"a_twice_b_once", [][]string{{"x.com", "x.com"}, {"x.com"}}, []int{1, 1}, "B", 1},
	{"a_once_b_twice", [][]string{{"x.com"}, {"x.com", "x.com"}}, []int{1, 1}, "B", 1},
	{"abc", [][]string{{"x.com"}, {"x.com"}, {"x.com"}}, []int{1, 1, 1}, "C", 2},
}

func TestCrossSourceSemantics(t *testing.T) {
	for _, hashMode := range []string{"real", "forced"} {
		for _, c := range crossCases {
			t.Run(hashMode+"/"+c.name, func(t *testing.T) {
				defer obs.Capture(t)()
				dir := t.TempDir()
				var srcs []Source
				var ids []string
				for i, f := range c.files {
					id := string(rune('A' + i))
					ids = append(ids, id)
					srcs = append(srcs, Source{ID: id, Path: writeHosts(t, dir, id+".txt", f)})
				}
				var set *Set
				var stats []Stats
				var err error
				if hashMode == "real" {
					set, stats, err = Load(srcs)
				} else {
					set = newSet(ids, constHash)
					stats, err = set.load(srcs)
				}
				if err != nil {
					t.Fatal(err)
				}
				for i, st := range stats {
					if st.Entries != c.entries[i] {
						t.Errorf("%s Entries = %d, want %d", st.ID, st.Entries, c.entries[i])
					}
				}
				if id, m, ok := set.Match("x.com"); !ok || id != c.winner || m != "x.com" {
					t.Errorf("Match = (%q,%q,%v), want %s", id, m, ok, c.winner)
				}
				if got := countInfo(t); got != c.infos {
					t.Errorf("Info logs = %d, want %d", got, c.infos)
				}
			})
		}
	}
}

func TestListIndexUpperByte(t *testing.T) {
	ids := make([]string, maxSources)
	for i := range ids {
		ids[i] = fmt.Sprintf("list%d", i)
	}
	for name, hash := range map[string]func(string) uint64{"real": newHash(), "forced": constHash} {
		t.Run(name, func(t *testing.T) {
			s := newSet(ids, hash)
			for _, i := range []uint16{0, 255, 256, 65534} {
				if _, existed := s.add(fmt.Sprintf("n%d.test", i), i); existed {
					t.Fatalf("n%d.test reported as existing", i)
				}
			}
			for _, i := range []int{0, 255, 256, 65534} {
				id, m, ok := s.Match(fmt.Sprintf("x.n%d.test", i))
				if !ok || id != ids[i] || m != fmt.Sprintf("n%d.test", i) {
					t.Errorf("index %d: Match = (%q,%q,%v), want %q", i, id, m, ok, ids[i])
				}
			}
		})
	}
}
