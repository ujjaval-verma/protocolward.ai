// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

func TestRamp(t *testing.T) {
	cases := []struct{ x, lo, hi, want float64 }{
		{0, 1, 2, 0}, {1, 1, 2, 0}, {1.5, 1, 2, 0.5}, {2, 1, 2, 1}, {9, 1, 2, 1},
	}
	for _, c := range cases {
		if got := ramp(c.x, c.lo, c.hi); math.Abs(got-c.want) > 1e-12 {
			t.Errorf("ramp(%v,%v,%v) = %v, want %v", c.x, c.lo, c.hi, got, c.want)
		}
	}
}

func TestWeightsSumToOne(t *testing.T) {
	sum := weightNgram + weightEntropy + weightDigit + weightConsonant + weightLength
	if math.Abs(sum-1) > 1e-12 {
		t.Fatalf("feature weights sum to %v, want 1", sum)
	}
}

// golden pins the verdict and the top reason for a fixed name set. A
// re-tune that flips any row must update this table deliberately.
var golden = []struct {
	host    string
	verdict schema.Verdict
	top     string // top reason code; "" means Reasons must be nil
}{
	{"google.com", schema.VerdictBenign, ""},
	{"github.com", schema.VerdictBenign, ""},
	{"wikipedia.org", schema.VerdictBenign, ""},
	{"fonts.gstatic.com", schema.VerdictBenign, ""},
	{"googleusercontent.com", schema.VerdictBenign, ""},
	{"d1x2y3.cloudfront.net", schema.VerdictBenign, ""},
	// The next two exercise the unscored path (local-use TLD / home.arpa),
	// not the scorer; they remain as regression pins for that path.
	{"printer-admin.lan", schema.VerdictBenign, ""},
	{"nas-backup.home.arpa", schema.VerdictBenign, ""},
	{"qq.com", schema.VerdictBenign, ""},
	{"163.com", schema.VerdictBenign, ""},
	{"intgmxdeadnxuyla.com", schema.VerdictMalicious, schema.ReasonRareNgrams},
	{"kalcepubqekeuaypadb.com", schema.VerdictMalicious, schema.ReasonRareNgrams},
	{"qwkjxzpvtr.net", schema.VerdictMalicious, schema.ReasonRareNgrams},
	{"8094deb269cb149e6250b7422f4a3acc.info", schema.VerdictMalicious, schema.ReasonRareNgrams},
	{"e3c1a2b4.com", schema.VerdictMalicious, schema.ReasonRareNgrams},
	// Benign but with Score in [0.2,0.5) and Reasons present.
	{"xkcd.com", schema.VerdictBenign, schema.ReasonRareNgrams},
}

func TestAssess_Golden(t *testing.T) {
	l := New()
	for _, g := range golden {
		a, err := l.Assess(context.Background(), model.Input{Hostname: g.host})
		if err != nil {
			t.Fatalf("Assess(%q) err = %v", g.host, err)
		}
		if a.Verdict != g.verdict {
			t.Errorf("Assess(%q).Verdict = %v (score %.3f), want %v", g.host, a.Verdict, a.Score, g.verdict)
		}
		switch {
		case g.top == "" && a.Reasons != nil:
			t.Errorf("Assess(%q).Reasons = %+v, want nil (score %.3f)", g.host, a.Reasons, a.Score)
		case g.top != "" && (len(a.Reasons) == 0 || a.Reasons[0].Code != g.top):
			t.Errorf("Assess(%q).Reasons = %+v, want top code %q", g.host, a.Reasons, g.top)
		}
	}
}

func TestAssess_ScoreAndReasonInvariants(t *testing.T) {
	known := map[string]bool{
		schema.ReasonHighEntropy: true, schema.ReasonRareNgrams: true, schema.ReasonDigitHeavy: true,
		schema.ReasonConsonantRun: true, schema.ReasonLongLabel: true,
	}
	l := New()
	for _, g := range golden {
		a, _ := l.Assess(context.Background(), model.Input{Hostname: g.host})
		if a.Score < 0 || a.Score > 1 {
			t.Errorf("%q: Score %.3f outside [0,1]", g.host, a.Score)
		}
		if (a.Score >= maliciousThreshold) != (a.Verdict == schema.VerdictMalicious) {
			t.Errorf("%q: Score %.3f inconsistent with Verdict %v at T_mal %.2f", g.host, a.Score, a.Verdict, maliciousThreshold)
		}
		if a.Verdict == schema.VerdictBenign && a.Score < quietScore && a.Reasons != nil {
			t.Errorf("%q: quiet benign carries reasons %+v", g.host, a.Reasons)
		}
		sum := 0.0
		for i, r := range a.Reasons {
			if !known[r.Code] {
				t.Errorf("%q: unknown reason code %q", g.host, r.Code)
			}
			if r.Weight < reasonFloor {
				t.Errorf("%q: reason %q weight %.3f below floor", g.host, r.Code, r.Weight)
			}
			if len(r.Detail) == 0 || len(r.Detail) > 120 {
				t.Errorf("%q: reason %q detail length %d, want 1..120", g.host, r.Code, len(r.Detail))
			}
			if i > 0 && r.Weight > a.Reasons[i-1].Weight {
				t.Errorf("%q: reasons not sorted by weight desc: %+v", g.host, a.Reasons)
			}
			sum += r.Weight
		}
		if sum > a.Score+1e-9 {
			t.Errorf("%q: reason weights sum %.3f exceed Score %.3f", g.host, sum, a.Score)
		}
	}
}

func TestAssess_DetailNeverEchoesLabel(t *testing.T) {
	a, _ := New().Assess(context.Background(), model.Input{Hostname: "qwkjxzpvtr.net"})
	for _, r := range a.Reasons {
		if strings.Contains(r.Detail, "qwkjxzpvtr") {
			t.Errorf("reason %q detail %q echoes the hostname", r.Code, r.Detail)
		}
	}
}

func TestAssess_ShortLabelsAreDamped(t *testing.T) {
	l := New()
	for _, h := range []string{"x.com", "qq.com", "jd.com", "t.co"} {
		a, _ := l.Assess(context.Background(), model.Input{Hostname: h})
		if a.Verdict != schema.VerdictBenign {
			t.Errorf("Assess(%q) = %v (score %.3f), want Benign", h, a.Verdict, a.Score)
		}
		if a.Score >= quietScore {
			t.Errorf("Assess(%q) score %.3f, want < quietScore %.2f (damping)", h, a.Score, quietScore)
		}
	}
}

func TestClassify_EqualsAssessVerdict(t *testing.T) {
	l := New()
	for _, g := range golden {
		in := model.Input{Hostname: g.host}
		a, _ := l.Assess(context.Background(), in)
		v, err := l.Classify(context.Background(), in)
		if err != nil || v != a.Verdict {
			t.Errorf("Classify(%q) = %v, %v; Assess verdict %v", g.host, v, err, a.Verdict)
		}
	}
}

func TestAssess_HonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Assess(ctx, model.Input{Hostname: "google.com"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Assess(cancelled ctx) err = %v, want context.Canceled", err)
	}
}

func TestLexical_ConcurrentAssessIsDeterministic(t *testing.T) {
	l := New()
	want := make([]schema.Assessment, len(golden))
	for i, g := range golden {
		want[i], _ = l.Assess(context.Background(), model.Input{Hostname: g.host})
	}
	var wg sync.WaitGroup
	errs := make(chan string, 8*len(golden))
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, g := range golden {
				got, _ := l.Assess(context.Background(), model.Input{Hostname: g.host})
				if got.Score != want[i].Score || got.Verdict != want[i].Verdict {
					errs <- g.host
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for h := range errs {
		t.Errorf("concurrent Assess(%q) diverged from sequential result", h)
	}
}

// TestPackage_NoIOImports keeps pkg/detect wasm-safe and side-effect free.
func TestPackage_NoIOImports(t *testing.T) {
	forbidden := map[string]bool{
		"os": true, "os/exec": true, "net": true, "net/http": true, "syscall": true,
		"io/ioutil": true, "unsafe": true, "plugin": true,
		"protocolward.ai/ward/internal": true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if forbidden[p] || p == "os" || strings.HasPrefix(p, "os/") ||
				p == "net" || strings.HasPrefix(p, "net/") || strings.HasPrefix(p, "protocolward.ai/ward/internal/") {
				t.Errorf("%s imports %q; pkg/detect must stay I/O-free and wasm-safe", f, p)
			}
		}
	}
}
