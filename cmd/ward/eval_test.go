// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"protocolward.ai/ward/pkg/detect"
	pmodel "protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

// fakeClassifier maps Hostname → Verdict via a static lookup. Anything not
// in the map returns VerdictBenign (matches wardtestmodel's default).
type fakeClassifier struct {
	m   map[string]schema.Verdict
	err error // when non-nil, every Classify call returns this error
}

func (f *fakeClassifier) Classify(_ context.Context, in pmodel.Input) (schema.Verdict, error) {
	if f.err != nil {
		return 0, f.err
	}
	if v, ok := f.m[in.Hostname]; ok {
		return v, nil
	}
	return schema.VerdictBenign, nil
}

func writeSuite(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write suite: %v", err)
	}
	return path
}

func TestEvalLoadSuite_ParsesValidRecords(t *testing.T) {
	body := `{"hostname":"ads-tracker.example","expected_verdict":"telemetry","label":"adtech"}
{"hostname":"example.com","expected_verdict":"benign","label":"benign-news"}
{"hostname":"download-now.evil.test","expected_verdict":"malicious","label":"malware"}
`
	path := writeSuite(t, "v.jsonl", body)
	records, err := loadEvalSuite(path)
	if err != nil {
		t.Fatalf("loadEvalSuite: %v", err)
	}
	if got, want := len(records), 3; got != want {
		t.Fatalf("len(records)=%d want %d", got, want)
	}
	if records[0].Hostname != "ads-tracker.example" || records[0].ExpectedVerdict != schema.VerdictTelemetry || records[0].Label != "adtech" {
		t.Errorf("record[0] = %#v", records[0])
	}
	if records[2].ExpectedVerdict != schema.VerdictMalicious {
		t.Errorf("record[2].ExpectedVerdict = %v want Malicious", records[2].ExpectedVerdict)
	}
}

func TestEvalLoadSuite_SkipsBlankLines(t *testing.T) {
	body := `
{"hostname":"a.test","expected_verdict":"benign","label":"x"}

{"hostname":"b.test","expected_verdict":"benign","label":"x"}
`
	path := writeSuite(t, "blanks.jsonl", body)
	records, err := loadEvalSuite(path)
	if err != nil {
		t.Fatalf("loadEvalSuite: %v", err)
	}
	if got, want := len(records), 2; got != want {
		t.Fatalf("len(records)=%d want %d", got, want)
	}
}

func TestEvalLoadSuite_RejectsUnknownVerdict(t *testing.T) {
	body := `{"hostname":"a","expected_verdict":"sketchy","label":"x"}` + "\n"
	path := writeSuite(t, "bad.jsonl", body)
	if _, err := loadEvalSuite(path); err == nil {
		t.Fatalf("expected error for unknown verdict")
	}
}

func TestEvalLoadSuite_RejectsMissingFields(t *testing.T) {
	body := `{"hostname":"","expected_verdict":"benign","label":"x"}` + "\n"
	path := writeSuite(t, "empty-host.jsonl", body)
	if _, err := loadEvalSuite(path); err == nil {
		t.Fatalf("expected error for empty hostname")
	}

	body = `{"hostname":"a","expected_verdict":"benign","label":""}` + "\n"
	path = writeSuite(t, "empty-label.jsonl", body)
	if _, err := loadEvalSuite(path); err == nil {
		t.Fatalf("expected error for empty label")
	}
}

func TestEvalLoadSuite_FileNotFound(t *testing.T) {
	if _, err := loadEvalSuite("/no/such/path.jsonl"); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestEvalRun_EmptyFixtureIsHarnessError(t *testing.T) {
	path := writeSuite(t, "empty.jsonl", "")
	var out bytes.Buffer
	err := evalRunWith(&out, evalOpts{SuitePath: path, Threshold: 0.85}, &fakeClassifier{})
	var se *serveError
	if !errors.As(err, &se) {
		t.Fatalf("expected *serveError, got %T (%v)", err, err)
	}
	if se.Code != 2 {
		t.Fatalf("exit code = %d want 2 (harness error)", se.Code)
	}
	if !strings.Contains(se.Message, "fixture contains no records") {
		t.Errorf("message = %q; want 'fixture contains no records'", se.Message)
	}
}

func TestEvalRun_MissingSuiteFlagIsHarnessError(t *testing.T) {
	var out bytes.Buffer
	err := evalRun(&out, evalOpts{SuitePath: "", Threshold: 0.85})
	var se *serveError
	if !errors.As(err, &se) {
		t.Fatalf("expected *serveError, got %T (%v)", err, err)
	}
	if se.Code != 2 {
		t.Fatalf("exit code = %d want 2", se.Code)
	}
}

func TestEvalScore_AllCorrect(t *testing.T) {
	records := []evalRecord{
		{Hostname: "a.test", ExpectedVerdict: schema.VerdictBenign, Label: "benign"},
		{Hostname: "b.test", ExpectedVerdict: schema.VerdictMalicious, Label: "malware"},
		{Hostname: "c.test", ExpectedVerdict: schema.VerdictTelemetry, Label: "adtech"},
	}
	clf := &fakeClassifier{m: map[string]schema.Verdict{
		"b.test": schema.VerdictMalicious,
		"c.test": schema.VerdictTelemetry,
	}}
	res, err := scoreSuite(context.Background(), clf, records)
	if err != nil {
		t.Fatalf("scoreSuite: %v", err)
	}
	if res.Records != 3 || res.Correct != 3 {
		t.Errorf("records=%d correct=%d", res.Records, res.Correct)
	}
	if res.Accuracy != 1.0 {
		t.Errorf("accuracy=%v want 1.0", res.Accuracy)
	}
	if got := res.ByLabel["malware"]; got.Records != 1 || got.Correct != 1 {
		t.Errorf("by_label[malware] = %+v", got)
	}
	if got := res.ByLabel["benign"]; got.Records != 1 || got.Correct != 1 {
		t.Errorf("by_label[benign] = %+v", got)
	}
}

func TestEvalScore_PartialAccuracy(t *testing.T) {
	records := []evalRecord{
		{Hostname: "a", ExpectedVerdict: schema.VerdictMalicious, Label: "malware"},
		{Hostname: "b", ExpectedVerdict: schema.VerdictMalicious, Label: "malware"},
		{Hostname: "c", ExpectedVerdict: schema.VerdictBenign, Label: "benign"},
		{Hostname: "d", ExpectedVerdict: schema.VerdictBenign, Label: "benign"},
	}
	// Classifier gets b + c + d right; misses a (returns benign).
	clf := &fakeClassifier{m: map[string]schema.Verdict{
		"b": schema.VerdictMalicious,
	}}
	res, err := scoreSuite(context.Background(), clf, records)
	if err != nil {
		t.Fatalf("scoreSuite: %v", err)
	}
	if res.Correct != 3 || res.Records != 4 {
		t.Errorf("correct=%d records=%d", res.Correct, res.Records)
	}
	if res.Accuracy != 0.75 {
		t.Errorf("accuracy=%v want 0.75", res.Accuracy)
	}
	if got := res.ByLabel["malware"]; got.Correct != 1 || got.Records != 2 {
		t.Errorf("by_label[malware] = %+v want {Records:2 Correct:1}", got)
	}
}

func TestEvalRun_PassAboveThreshold(t *testing.T) {
	body := `{"hostname":"a","expected_verdict":"malicious","label":"malware"}
{"hostname":"b","expected_verdict":"benign","label":"benign"}
{"hostname":"c","expected_verdict":"benign","label":"benign"}
`
	path := writeSuite(t, "pass.jsonl", body)
	clf := &fakeClassifier{m: map[string]schema.Verdict{
		"a": schema.VerdictMalicious,
	}}
	var out bytes.Buffer
	err := evalRunWith(&out, evalOpts{SuitePath: path, Threshold: 0.85}, clf)
	if err != nil {
		t.Fatalf("evalRunWith: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "PASS") {
		t.Errorf("stdout missing PASS marker: %q", got)
	}
	if !strings.Contains(got, "3/3 correct") {
		t.Errorf("stdout missing summary: %q", got)
	}
	if !strings.Contains(got, `"accuracy":1`) {
		t.Errorf("stdout missing JSON detail: %q", got)
	}
}

func TestEvalRun_FailBelowThreshold(t *testing.T) {
	body := `{"hostname":"a","expected_verdict":"malicious","label":"malware"}
{"hostname":"b","expected_verdict":"malicious","label":"malware"}
{"hostname":"c","expected_verdict":"malicious","label":"malware"}
{"hostname":"d","expected_verdict":"malicious","label":"malware"}
`
	path := writeSuite(t, "fail.jsonl", body)
	// Classifier gets only 1/4 right.
	clf := &fakeClassifier{m: map[string]schema.Verdict{
		"a": schema.VerdictMalicious,
	}}
	var out bytes.Buffer
	err := evalRunWith(&out, evalOpts{SuitePath: path, Threshold: 0.85}, clf)
	var se *serveError
	if !errors.As(err, &se) {
		t.Fatalf("expected *serveError, got %T (%v)", err, err)
	}
	if se.Code != 1 {
		t.Fatalf("exit code = %d want 1 (regression)", se.Code)
	}
	if !strings.Contains(out.String(), "FAIL") {
		t.Errorf("stdout missing FAIL marker: %q", out.String())
	}
	if !strings.Contains(out.String(), "1/4 correct") {
		t.Errorf("stdout missing summary: %q", out.String())
	}
}

func TestEvalRun_ClassifierUnavailableIsHarnessError(t *testing.T) {
	body := `{"hostname":"a","expected_verdict":"benign","label":"benign"}` + "\n"
	path := writeSuite(t, "unavail.jsonl", body)
	clf := &fakeClassifier{err: errors.New("model unavailable")}
	var out bytes.Buffer
	err := evalRunWith(&out, evalOpts{SuitePath: path, Threshold: 0.85}, clf)
	var se *serveError
	if !errors.As(err, &se) {
		t.Fatalf("expected *serveError, got %T (%v)", err, err)
	}
	if se.Code != 2 {
		t.Fatalf("exit code = %d want 2 (harness error)", se.Code)
	}
}

func TestEvalScore_ClassifierErrorAborts(t *testing.T) {
	records := []evalRecord{
		{Hostname: "a", ExpectedVerdict: schema.VerdictBenign, Label: "benign"},
	}
	clf := &fakeClassifier{err: errors.New("model unavailable")}
	if _, err := scoreSuite(context.Background(), clf, records); err == nil {
		t.Fatalf("expected classifier error to propagate")
	}
}

// TestEvalFixtureSelfConsistency loads the committed v0.2 fixture and
// asserts the invariants documented in the SP10d spec: ≥50 records, mix
// of ~30 benign / ~10 telemetry / ~10 malicious with ≥5 prompt-injection
// records, and self-consistency with wardtestmodel's substring mapping
// (every malicious host contains "evil"; every telemetry host contains
// "telemetry"; no benign host contains either substring). DOD bullet 15
// loads this fixture against `wardtestmodel -malicious-substring evil
// -telemetry-substring telemetry` and expects 100% accuracy.
func TestEvalFixtureSelfConsistency(t *testing.T) {
	const fixturePath = "../../testdata/eval/v0.2.jsonl"
	records, err := loadEvalSuite(fixturePath)
	if err != nil {
		t.Fatalf("loadEvalSuite: %v", err)
	}
	if len(records) < 50 {
		t.Fatalf("len(records)=%d, want >= 50", len(records))
	}

	var benign, telemetry, malicious, promptInjection int
	for i, r := range records {
		hasEvil := strings.Contains(r.Hostname, "evil")
		hasTelem := strings.Contains(r.Hostname, "telemetry")
		switch r.ExpectedVerdict {
		case schema.VerdictBenign:
			benign++
			if hasEvil || hasTelem {
				t.Errorf("record %d (%q): benign host contains evil/telemetry substring", i, r.Hostname)
			}
		case schema.VerdictTelemetry:
			telemetry++
			if !hasTelem {
				t.Errorf("record %d (%q): telemetry host missing 'telemetry' substring", i, r.Hostname)
			}
			if hasEvil {
				t.Errorf("record %d (%q): telemetry host contains 'evil' substring (wardtestmodel maps to malicious)", i, r.Hostname)
			}
		case schema.VerdictMalicious:
			malicious++
			if !hasEvil {
				t.Errorf("record %d (%q): malicious host missing 'evil' substring", i, r.Hostname)
			}
		}
		if r.Label == "prompt-injection" {
			promptInjection++
		}
	}

	if benign < 25 {
		t.Errorf("benign count=%d, want >= 25", benign)
	}
	if telemetry < 8 {
		t.Errorf("telemetry count=%d, want >= 8", telemetry)
	}
	if malicious < 8 {
		t.Errorf("malicious count=%d, want >= 8", malicious)
	}
	if promptInjection < 5 {
		t.Errorf("prompt-injection records=%d, want >= 5 (vision.md Key Risk #6)", promptInjection)
	}
}

// A ward.yaml with model: {builtin: lexical} must make `ward eval --config`
// score the in-process detector, not try to spawn an empty argv.
func TestBuildClassifier_BuiltinConfig_UsesLexical(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "ward.yaml")
	body := `listen: "127.0.0.1:5354"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
model:
  builtin: lexical
`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	clf, cleanup, err := buildClassifier(cfg)
	if err != nil {
		t.Fatalf("buildClassifier: %v", err)
	}
	defer cleanup()
	if _, ok := clf.(*detect.Lexical); !ok {
		t.Errorf("classifier = %T, want *detect.Lexical", clf)
	}
}

// (l) Pin the no-model-stanza remediation: it must steer the operator to
// both in-process (model.builtin / --builtin) and sibling (model.command)
// options, and exit 2.
func TestBuildClassifier_NoModelStanza_Remediation(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "ward.yaml")
	body := `listen: "127.0.0.1:5354"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, cleanup, err := buildClassifier(cfg)
	defer cleanup()
	var se *serveError
	if !errors.As(err, &se) || se.Code != 2 {
		t.Fatalf("err = %v, want *serveError code 2", err)
	}
	const want = "add model: {builtin: lexical} (in-process detector) or a model.command stanza to ward.yaml, or use ward eval --builtin"
	if se.Remediation != want {
		t.Errorf("remediation = %q, want %q", se.Remediation, want)
	}
	if !strings.Contains(se.Message, "no model: stanza") {
		t.Errorf("message = %q, want it to name the missing model: stanza", se.Message)
	}
}
