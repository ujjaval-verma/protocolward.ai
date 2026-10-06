// SPDX-License-Identifier: Apache-2.0

package model_test

import (
	"context"
	"testing"

	"protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

// staticClassifier is a Classify-returns-fixed-Verdict test double. Lives
// in _test.go so the production package stays surface-minimal (one
// interface, one struct).
type staticClassifier struct {
	Verdict schema.Verdict
}

func (s staticClassifier) Classify(_ context.Context, _ model.Input) (schema.Verdict, error) {
	return s.Verdict, nil
}

// Compile-time signature assertion: staticClassifier satisfies the
// Classifier interface. Asserted on the value form (matching the
// receiver shape SP10b adapters are most likely to use); the pointer
// form is promoted automatically by Go's method-set rules.
var _ model.Classifier = staticClassifier{}

// TestClassifier_ContractRoundTrip proves the surface is wired end-to-end:
// an Input is constructible from a test that imports nothing from
// internal/, the Classifier method runs, and the typed Verdict flows back
// to the caller. This is the tracer-bullet for the pkg/model surface.
func TestClassifier_ContractRoundTrip(t *testing.T) {
	var c model.Classifier = staticClassifier{Verdict: schema.VerdictMalicious}
	got, err := c.Classify(context.Background(), model.Input{
		Hostname:    "evil.example.com",
		ClientHints: []string{"hint-a", "hint-b"},
		UserAgent:   "Mozilla/5.0",
	})
	if err != nil {
		t.Fatalf("Classify returned err = %v, want nil", err)
	}
	if got != schema.VerdictMalicious {
		t.Errorf("Classify returned %v, want VerdictMalicious", got)
	}
}

// staticAssessor implements both Classifier and Assessor, the shape
// pkg/detect.Lexical takes.
type staticAssessor struct {
	A schema.Assessment
}

func (s staticAssessor) Classify(_ context.Context, _ model.Input) (schema.Verdict, error) {
	return s.A.Verdict, nil
}

func (s staticAssessor) Assess(_ context.Context, _ model.Input) (schema.Assessment, error) {
	return s.A, nil
}

var (
	_ model.Classifier = staticAssessor{}
	_ model.Assessor   = staticAssessor{}
)

// TestAssessor_OptionalUpgradeFromClassifier pins the intended call
// pattern: hold a Classifier, type-assert for Assessor.
func TestAssessor_OptionalUpgradeFromClassifier(t *testing.T) {
	want := schema.Assessment{Verdict: schema.VerdictMalicious, Score: 0.9}
	var c model.Classifier = staticAssessor{A: want}
	as, ok := c.(model.Assessor)
	if !ok {
		t.Fatal("staticAssessor does not satisfy model.Assessor")
	}
	got, err := as.Assess(context.Background(), model.Input{Hostname: "qwkjxzpvtr.net"})
	if err != nil || got.Verdict != want.Verdict || got.Score != want.Score {
		t.Errorf("Assess = %+v, %v; want %+v, nil", got, err, want)
	}
	if _, ok := model.Classifier(staticClassifier{}).(model.Assessor); ok {
		t.Error("staticClassifier unexpectedly satisfies Assessor; the interface must stay optional")
	}
}
