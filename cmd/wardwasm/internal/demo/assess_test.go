// SPDX-License-Identifier: Apache-2.0

package demo_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"protocolward.ai/ward/cmd/wardwasm/internal/demo"
	"protocolward.ai/ward/pkg/detect"
	"protocolward.ai/ward/pkg/model"
)

var assessNames = []string{"github.com", "fonts.gstatic.com", "d1x2y3.cloudfront.net", "xjw3kq9vbz7tq2lmpr.com"}

// The demo must show the real detector's output, unaltered.
func TestAssess_IsAFaithfulPassthroughOfTheDetector(t *testing.T) {
	ctx := context.Background()
	lex := detect.New()
	d := demo.New()
	for _, name := range assessNames {
		want, err := lex.Assess(ctx, model.Input{Hostname: name})
		if err != nil {
			t.Fatalf("detect.Assess(%q): %v", name, err)
		}
		got, err := d.Assess(ctx, name)
		if err != nil {
			t.Fatalf("demo.Assess(%q): %v", name, err)
		}
		wantVerdict, err := want.Verdict.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		if strconv.Quote(got.Verdict) != string(wantVerdict) {
			t.Errorf("%s: verdict %q; want %s", name, got.Verdict, wantVerdict)
		}
		if got.Score != want.Score || got.Score < 0 || got.Score > 1 {
			t.Errorf("%s: score %v; want %v within [0,1]", name, got.Score, want.Score)
		}
		if got.Reasons == nil || len(got.Reasons) != len(want.Reasons) {
			t.Fatalf("%s: reasons %v; want %d non-nil", name, got.Reasons, len(want.Reasons))
		}
		for i, r := range want.Reasons {
			if g := got.Reasons[i]; g.Code != r.Code || g.Detail != r.Detail || g.Weight != r.Weight {
				t.Errorf("%s: reason[%d] = %+v; want %+v", name, i, g, r)
			}
		}
	}
}

func TestAssess_NormalizesInput(t *testing.T) {
	ctx := context.Background()
	d := demo.New()
	canon, err := d.Assess(ctx, "github.com")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	messy, err := d.Assess(ctx, "  GitHub.COM.  ")
	if err != nil {
		t.Fatalf("Assess(messy): %v", err)
	}
	if canon.Verdict != messy.Verdict || canon.Score != messy.Score {
		t.Errorf("messy input assessed differently: %+v vs %+v", messy, canon)
	}
}

func TestAssess_RejectsInvalidHostnames(t *testing.T) {
	d := demo.New()
	for _, q := range []string{"", strings.Repeat("a", 300), "bad host.com"} {
		_, err := d.Assess(context.Background(), q)
		if !errors.Is(err, demo.ErrInvalidHostname) {
			t.Errorf("Assess(%.20q) err = %v; want ErrInvalidHostname", q, err)
		}
		if err != nil && demo.ErrorMessage(err) != "not a valid hostname" {
			t.Errorf("ErrorMessage = %q", demo.ErrorMessage(err))
		}
	}
}

// Flag-only (ADR-0006): assessing a name must not change what Decide does,
// even with lists loaded. The name is malicious per the detector and must
// still forward.
func TestAssess_DoesNotInfluenceDecide(t *testing.T) {
	d := mustInit(t, fixture)
	name := "xjw3kq9vbz7tq2lmpr.com"
	a, err := d.Assess(context.Background(), name)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if a.Verdict != "malicious" {
		t.Fatalf("precondition: %s verdict %q; pick a name the detector flags", name, a.Verdict)
	}
	got, err := d.Decide(name)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if want := (demo.Decision{Action: demo.ActionForward, Source: demo.SourceForward}); got != want {
		t.Errorf("Decide after Assess = %+v; want %+v", got, want)
	}
}

func TestAssessment_MapMatchesJSSurface(t *testing.T) {
	a := demo.Assessment{
		Verdict: "malicious",
		Score:   0.91,
		Reasons: []demo.Reason{{Code: "high_entropy", Detail: "label entropy 4.1 bits", Weight: 0.5}},
	}
	m := a.Map()
	if len(m) != 3 || m["verdict"] != "malicious" || m["score"] != 0.91 {
		t.Fatalf("Map = %v; want exactly verdict/score/reasons", m)
	}
	reasons, ok := m["reasons"].([]any)
	if !ok || len(reasons) != 1 {
		t.Fatalf("reasons = %#v; want []any of length 1", m["reasons"])
	}
	r, ok := reasons[0].(map[string]any)
	if !ok || len(r) != 3 || r["code"] != "high_entropy" || r["detail"] != "label entropy 4.1 bits" || r["weight"] != 0.5 {
		t.Errorf("reason = %#v; want {code, detail, weight}", reasons[0])
	}
	assertJSValueOfSafe(t, "assessment", m)

	empty := demo.Assessment{Verdict: "benign", Reasons: []demo.Reason{}}.Map()
	if rs, ok := empty["reasons"].([]any); !ok || rs == nil {
		t.Errorf("benign reasons = %#v; want empty non-nil []any so JS sees []", empty["reasons"])
	}
}
