// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleCSV = `GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs
1,1,google.com,com,1,1,google.com,com,1,1,1,1
2,2,facebook.com,com,1,1,facebook.com,com,2,2,1,1
3,1,xn--80ak6aa92e.com,com,1,1,x,com,3,1,1,1
4,1,bbc.co.uk,uk,1,1,bbc.co.uk,uk,4,1,1,1
5,1,ex_ample.org,org,1,1,ex_ample.org,org,5,1,1,1
6,3,wikipedia.org,org,1,1,wikipedia.org,org,6,3,1,1
7,4,github.com,com,1,1,github.com,com,7,4,1,1
`

func TestReadMajestic_SplitsTrainAndHoldout(t *testing.T) {
	o := options{trainTop: 6, holdoutTop: 6, holdoutEvery: 3}
	train, holdout, err := readMajestic(strings.NewReader(sampleCSV), o)
	if err != nil {
		t.Fatalf("readMajestic: %v", err)
	}
	// Rank 3 (punycode) and 5 ('_') are skipped before the holdout check,
	// rank 6 is held out, rank 7 is beyond trainTop.
	if got, want := strings.Join(train, ","), "google,facebook,bbc"; got != want {
		t.Errorf("train = %q, want %q", got, want)
	}
	if got, want := strings.Join(holdout, ","), "wikipedia.org"; got != want {
		t.Errorf("holdout = %q, want %q", got, want)
	}
}

func TestBuildTable_HeaderAndSize(t *testing.T) {
	b := buildTable([]string{"google", "github"})
	v := len(alphabet)
	if string(b[:4]) != "PWNG" || b[4] != 1 || b[5] != scale || int(b[6]) != v {
		t.Fatalf("bad header % x", b[:7])
	}
	if string(b[7:7+v]) != alphabet {
		t.Fatalf("alphabet in header = %q", b[7:7+v])
	}
	if got, want := len(b), 7+v+v*v*v; got != want {
		t.Fatalf("len = %d, want %d", got, want)
	}
}

func TestBuildTable_SeenTrigramsAreCheaper(t *testing.T) {
	b := buildTable([]string{"google", "google", "google"})
	v := len(alphabet)
	at := func(x, y, z byte) byte { return b[7+v+(sym(x)*v+sym(y))*v+sym(z)] }
	if seen, unseen := at('o', 'o', 'g'), at('q', 'x', 'z'); seen >= unseen {
		t.Errorf("cost(oog)=%d not below cost(qxz)=%d", seen, unseen)
	}
}

func TestBuildTable_Deterministic(t *testing.T) {
	in := []string{"google", "facebook", "wikipedia"}
	if !bytes.Equal(buildTable(in), buildTable(in)) {
		t.Fatal("buildTable is not deterministic")
	}
}

func TestWriteEval_EmitsLoadableJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.jsonl")
	if err := writeEval(path, []string{"google.com"}, []dgaRecord{{"qwkjxzpvtr.net", "dga-x"}}); err != nil {
		t.Fatalf("writeEval: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []evalLine
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l evalLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("bad line %q: %v", sc.Text(), err)
		}
		lines = append(lines, l)
	}
	want := []evalLine{{"google.com", "benign", "benign-majestic"}, {"qwkjxzpvtr.net", "malicious", "dga-x"}}
	if len(lines) != 2 || lines[0] != want[0] || lines[1] != want[1] {
		t.Errorf("lines = %+v, want %+v", lines, want)
	}
}

func TestGenerateDGA_ShapesAndDeterminism(t *testing.T) {
	a, b := generateDGA(20), generateDGA(20)
	if len(a) != 60 {
		t.Fatalf("len = %d, want 60", len(a))
	}
	count := map[string]int{}
	for i, r := range a {
		if r != b[i] {
			t.Fatalf("record %d differs between runs", i)
		}
		count[r.Label]++
		label, tld, _ := strings.Cut(r.Hostname, ".")
		switch r.Label {
		case "dga-wiki":
			if len(label) != 16 || tld != "com" {
				t.Errorf("wiki name %q", r.Hostname)
			}
		case "dga-ramnit":
			if len(label) < 8 || len(label) > 19 || strings.ContainsAny(label, "z0123456789") || tld != "com" {
				t.Errorf("ramnit name %q", r.Hostname)
			}
		case "dga-md5":
			if len(label) != 32 || strings.Trim(label, "0123456789abcdef") != "" || tld != "info" {
				t.Errorf("md5 name %q", r.Hostname)
			}
		default:
			t.Errorf("unexpected label %q", r.Label)
		}
	}
	for _, l := range []string{"dga-wiki", "dga-ramnit", "dga-md5"} {
		if count[l] != 20 {
			t.Errorf("%s count = %d, want 20", l, count[l])
		}
	}
}
