// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"protocolward.ai/ward/pkg/detect"
	"protocolward.ai/ward/pkg/schema"
)

func TestEvalScore_RecallAndFPR(t *testing.T) {
	records := []evalRecord{
		{Hostname: "m1", ExpectedVerdict: schema.VerdictMalicious, Label: "dga"},
		{Hostname: "m2", ExpectedVerdict: schema.VerdictMalicious, Label: "dga"},
		{Hostname: "m3", ExpectedVerdict: schema.VerdictMalicious, Label: "dga"},
		{Hostname: "m4", ExpectedVerdict: schema.VerdictMalicious, Label: "dga"},
		{Hostname: "b1", ExpectedVerdict: schema.VerdictBenign, Label: "benign"},
		{Hostname: "b2", ExpectedVerdict: schema.VerdictBenign, Label: "benign"},
		{Hostname: "t1", ExpectedVerdict: schema.VerdictTelemetry, Label: "adtech"},
	}
	clf := &fakeClassifier{m: map[string]schema.Verdict{
		"m1": schema.VerdictMalicious, "m2": schema.VerdictMalicious, "m3": schema.VerdictMalicious,
		"b2": schema.VerdictTelemetry, // a benign name flagged as anything non-benign is a false positive
	}}
	res, err := scoreSuite(context.Background(), clf, records)
	if err != nil {
		t.Fatalf("scoreSuite: %v", err)
	}
	if res.MaliciousRecall != 0.75 {
		t.Errorf("MaliciousRecall = %v, want 0.75", res.MaliciousRecall)
	}
	if res.BenignFPR != 0.5 {
		t.Errorf("BenignFPR = %v, want 0.5", res.BenignFPR)
	}
}

func TestEvalRun_RecallGateFailsEvenWhenAccuracyPasses(t *testing.T) {
	body := `{"hostname":"m1","expected_verdict":"malicious","label":"dga"}
{"hostname":"m2","expected_verdict":"malicious","label":"dga"}
{"hostname":"b1","expected_verdict":"benign","label":"benign"}
{"hostname":"b2","expected_verdict":"benign","label":"benign"}
{"hostname":"b3","expected_verdict":"benign","label":"benign"}
{"hostname":"b4","expected_verdict":"benign","label":"benign"}
{"hostname":"b5","expected_verdict":"benign","label":"benign"}
{"hostname":"b6","expected_verdict":"benign","label":"benign"}
{"hostname":"b7","expected_verdict":"benign","label":"benign"}
{"hostname":"b8","expected_verdict":"benign","label":"benign"}
`
	path := writeSuite(t, "gate.jsonl", body)
	clf := &fakeClassifier{m: map[string]schema.Verdict{"m1": schema.VerdictMalicious}} // 9/10 accuracy, recall 0.5
	var out bytes.Buffer
	err := evalRunWith(&out, evalOpts{SuitePath: path, Threshold: 0.85, MinRecall: 0.85, MaxFPR: 0.01}, clf)
	var se *serveError
	if !errors.As(err, &se) || se.Code != 1 {
		t.Fatalf("err = %v, want *serveError code 1", err)
	}
	if !strings.Contains(out.String(), "(0.90 ≥ 0.85) — PASS") {
		t.Errorf("accuracy line should still PASS: %q", out.String())
	}
	if !strings.Contains(out.String(), "malicious recall 0.500 (min 0.85), benign FPR 0.0000 (max 0.0100) — FAIL") {
		t.Errorf("gate line missing or wrong: %q", out.String())
	}
}

func TestEvalRun_NoGateLineWhenGatesDisabled(t *testing.T) {
	body := `{"hostname":"a","expected_verdict":"benign","label":"benign"}` + "\n"
	path := writeSuite(t, "nogate.jsonl", body)
	var out bytes.Buffer
	if err := evalRunWith(&out, evalOpts{SuitePath: path, Threshold: 0.85}, &fakeClassifier{}); err != nil {
		t.Fatalf("evalRunWith: %v", err)
	}
	if strings.Contains(out.String(), "malicious recall") {
		t.Errorf("gate line printed with gates disabled: %q", out.String())
	}
}

func TestEvalRun_BuiltinNeedsNoConfig(t *testing.T) {
	body := `{"hostname":"google.com","expected_verdict":"benign","label":"benign"}
{"hostname":"qwkjxzpvtr.net","expected_verdict":"malicious","label":"dga"}
`
	path := writeSuite(t, "builtin.jsonl", body)
	var out bytes.Buffer
	if err := evalRun(&out, evalOpts{SuitePath: path, Threshold: 1, Builtin: true}); err != nil {
		t.Fatalf("evalRun(--builtin): %v (stdout %q)", err, out.String())
	}
	if !strings.Contains(out.String(), "2/2 correct") {
		t.Errorf("stdout = %q, want 2/2 correct", out.String())
	}
}

func TestEvalRun_BuiltinRejectsConfig(t *testing.T) {
	path := writeSuite(t, "x.jsonl", `{"hostname":"a.com","expected_verdict":"benign","label":"b"}`+"\n")
	var out bytes.Buffer
	err := evalRun(&out, evalOpts{SuitePath: path, Threshold: 0.85, Builtin: true, ConfigPath: "ward.yaml"})
	var se *serveError
	if !errors.As(err, &se) || se.Code != 2 {
		t.Fatalf("err = %v, want *serveError code 2", err)
	}
}

func TestEvalRun_InvalidFixtureHostnameRemediation(t *testing.T) {
	path := writeSuite(t, "bad.jsonl", `{"hostname":"bad host.com","expected_verdict":"benign","label":"b"}`+"\n")
	var out bytes.Buffer
	err := evalRun(&out, evalOpts{SuitePath: path, Threshold: 0.85, Builtin: true})
	var se *serveError
	if !errors.As(err, &se) || se.Code != 2 {
		t.Fatalf("err = %v, want *serveError code 2", err)
	}
	if strings.Contains(se.Remediation, "ward.yaml") || strings.Contains(se.Remediation, "model") {
		t.Errorf("remediation %q points at ward.yaml/model; --builtin has neither", se.Remediation)
	}
	if !strings.Contains(se.Remediation, "fixture record") {
		t.Errorf("remediation %q should name the fixture record", se.Remediation)
	}
}

// TestEvalBuiltinLexicalTargets is the S1 acceptance gate: the real
// detector against testdata/eval/lexical-v1.jsonl must reach DGA recall
// ≥ 0.85 and benign FPR ≤ 1%. Skipped under -short (pre-push hook);
// runs under `make test` / `make ci`.
func TestEvalBuiltinLexicalTargets(t *testing.T) {
	if testing.Short() {
		t.Skip("lexical eval runs under make test, not -short")
	}
	records, err := loadEvalSuite("../../testdata/eval/lexical-v1.jsonl")
	if err != nil {
		t.Fatalf("loadEvalSuite: %v", err)
	}
	labels := map[string]int{}
	for _, r := range records {
		labels[r.Label]++
	}
	for _, l := range []string{"benign-majestic", "dga-wiki", "dga-ramnit", "dga-md5"} {
		if labels[l] < 450 {
			t.Errorf("fixture label %q has %d records, want ≥ 450", l, labels[l])
		}
	}
	res, err := scoreSuite(context.Background(), detect.New(), records)
	if err != nil {
		t.Fatalf("scoreSuite: %v", err)
	}
	t.Logf("recall=%.4f fpr=%.4f by_label=%+v", res.MaliciousRecall, res.BenignFPR, res.ByLabel)
	if res.MaliciousRecall < 0.85 {
		t.Errorf("DGA recall = %.4f, want ≥ 0.85", res.MaliciousRecall)
	}
	if res.BenignFPR > 0.01 {
		t.Errorf("benign FPR = %.4f, want ≤ 0.01", res.BenignFPR)
	}
	// dga-md5 (32 hex chars) is trivially separable and inflates the
	// headline recall; the letter-based families must clear the bar alone.
	wiki, ramnit := res.ByLabel["dga-wiki"], res.ByLabel["dga-ramnit"]
	letterRecall := float64(wiki.Correct+ramnit.Correct) / float64(wiki.Records+ramnit.Records)
	t.Logf("recall excluding dga-md5 = %.4f", letterRecall)
	if letterRecall < 0.85 {
		t.Errorf("DGA recall excluding dga-md5 = %.4f, want ≥ 0.85", letterRecall)
	}
}
