// SPDX-License-Identifier: Apache-2.0

package detect_test

import (
	"context"
	"testing"

	"protocolward.ai/ward/pkg/detect"
	"protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

// TestLexical_TracerBullet drives the public surface end to end: embedded
// table → hostname → features → typed Assessment, for one obvious DGA
// name and one household name.
func TestLexical_TracerBullet(t *testing.T) {
	l := detect.New()
	ctx := context.Background()

	dga, err := l.Assess(ctx, model.Input{Hostname: "qwkjxzpvtr.net"})
	if err != nil {
		t.Fatalf("Assess(qwkjxzpvtr.net) err = %v", err)
	}
	if dga.Verdict != schema.VerdictMalicious {
		t.Errorf("Assess(qwkjxzpvtr.net).Verdict = %v, want VerdictMalicious (score %.3f)", dga.Verdict, dga.Score)
	}
	if len(dga.Reasons) == 0 {
		t.Errorf("Assess(qwkjxzpvtr.net).Reasons is empty, want at least one reason")
	}
	if dga.Score < 0.5 || dga.Score > 1 {
		t.Errorf("Assess(qwkjxzpvtr.net).Score = %.3f, want in [0.5, 1]", dga.Score)
	}

	benign, err := l.Assess(ctx, model.Input{Hostname: "google.com"})
	if err != nil {
		t.Fatalf("Assess(google.com) err = %v", err)
	}
	if benign.Verdict != schema.VerdictBenign {
		t.Errorf("Assess(google.com).Verdict = %v, want VerdictBenign (score %.3f)", benign.Verdict, benign.Score)
	}

	v, err := l.Classify(ctx, model.Input{Hostname: "qwkjxzpvtr.net"})
	if err != nil || v != schema.VerdictMalicious {
		t.Errorf("Classify(qwkjxzpvtr.net) = %v, %v; want VerdictMalicious, nil", v, err)
	}
}
