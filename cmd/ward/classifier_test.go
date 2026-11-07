// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"protocolward.ai/ward/internal/config"
	"protocolward.ai/ward/internal/model"
	"protocolward.ai/ward/pkg/detect"
	pmodel "protocolward.ai/ward/pkg/model"
)

var sgrRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// captureStderr swaps os.Stderr for a pipe drained by a goroutine. The
// returned func restores os.Stderr and returns what was written with SGR
// sequences stripped (lipgloss styles from os.Stdout's profile, so a TTY
// stdout or CLICOLOR_FORCE=1 would add them). It is idempotent and also runs
// at t.Cleanup, so a t.Fatal still restores state.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	prev := os.Stderr
	os.Stderr = w
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	finished := false
	finish := func() string {
		if !finished {
			finished = true
			os.Stderr = prev
			_ = w.Close()
			<-done
			_ = r.Close()
		}
		return sgrRE.ReplaceAllString(buf.String(), "")
	}
	t.Cleanup(func() { finish() })
	return finish
}

func requireBin(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s not available: %v", path, err)
	}
}

// slogRecords decodes the JSON lines captureSlog collected.
func slogRecords(t *testing.T, s string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("slog line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func TestNewServeClassifier_NoModel_FastPathOnly(t *testing.T) {
	logs := captureSlog(t)
	stderr := captureStderr(t)
	c, closeFn, startFailed := newServeClassifier(config.Config{})
	if c != nil {
		t.Errorf("classifier = %T, want nil", c)
	}
	if startFailed {
		t.Error("startFailed = true, want false")
	}
	if closeFn == nil {
		t.Fatal("closeFn = nil, want non-nil")
	}
	closeFn()
	if got := logs.String(); got != "" {
		t.Errorf("slog output = %q, want empty", got)
	}
	if got := stderr(); got != "" {
		t.Errorf("stderr = %q, want empty", got)
	}
}

func TestNewServeClassifier_SpawnFailure_StartFailed(t *testing.T) {
	logs := captureSlog(t)
	stderr := captureStderr(t)
	c, closeFn, startFailed := newServeClassifier(config.Config{
		Model: &config.ModelConfig{Command: []string{"/nonexistent/ward-test-model"}},
	})
	if c != nil {
		t.Errorf("classifier = %T, want untyped nil", c)
	}
	if !startFailed {
		t.Error("startFailed = false, want true")
	}
	if closeFn == nil {
		t.Fatal("closeFn = nil, want non-nil")
	}
	closeFn()

	const rem = "fix model.command in ward.yaml, or remove the model: stanza to run fast-path-only"
	got := stderr()
	if !strings.HasPrefix(got, "model error\npolicy: model unavailable: ") {
		t.Errorf("stderr = %q, want prefix %q", got, "model error\npolicy: model unavailable: ")
	}
	if !strings.HasSuffix(got, "\nremediation: "+rem+"\n") {
		t.Errorf("stderr = %q, want remediation suffix", got)
	}
	lines := strings.Split(got, "\n")
	if len(lines) < 2 {
		t.Fatalf("stderr has %d lines, want >= 2: %q", len(lines), got)
	}
	errText := strings.TrimPrefix(lines[1], "policy: model unavailable: ")

	recs := slogRecords(t, logs.String())
	if len(recs) != 1 {
		t.Fatalf("slog records = %d (%s), want 1", len(recs), logs.String())
	}
	r := recs[0]
	if r["level"] != "WARN" || r["msg"] != "policy: model unavailable" {
		t.Errorf("record level/msg = %v/%v, want WARN/policy: model unavailable", r["level"], r["msg"])
	}
	if r["remediation"] != rem {
		t.Errorf("remediation = %v, want %q", r["remediation"], rem)
	}
	if e, _ := r["error"].(string); e == "" || e != errText {
		t.Errorf("error = %q, want non-empty and equal to stderr text %q", e, errText)
	}
	if strings.Contains(logs.String(), "policy: model loaded") {
		t.Errorf("unexpected loaded record: %s", logs.String())
	}
}

func TestNewServeClassifier_LoadedLog(t *testing.T) {
	cases := []struct {
		name  string
		cfg   *config.ModelConfig
		bin   string
		check func(t *testing.T, c any)
		want  string
	}{
		{
			name: "builtin",
			cfg:  &config.ModelConfig{Builtin: "lexical"},
			check: func(t *testing.T, c any) {
				if _, ok := c.(*detect.Lexical); !ok {
					t.Errorf("classifier = %T, want *detect.Lexical", c)
				}
			},
			want: `"level":"INFO","msg":"policy: model loaded","builtin":"lexical","mode":"flag-only"}`,
		},
		{
			name: "command",
			cfg:  &config.ModelConfig{Command: []string{"/bin/cat"}},
			bin:  "/bin/cat",
			check: func(t *testing.T, c any) {
				if _, ok := c.(*model.Adapter); !ok {
					t.Errorf("classifier = %T, want *model.Adapter", c)
				}
			},
			want: `"level":"INFO","msg":"policy: model loaded","command":"/bin/cat","argc":1}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.bin != "" {
				requireBin(t, tc.bin)
			}
			logs := captureSlog(t)
			stderr := captureStderr(t)
			c, closeFn, startFailed := newServeClassifier(config.Config{Model: tc.cfg})
			if startFailed {
				t.Error("startFailed = true, want false")
			}
			tc.check(t, c)
			closeFn()
			if recs := slogRecords(t, logs.String()); len(recs) != 1 {
				t.Errorf("slog records = %d (%s), want 1", len(recs), logs.String())
			}
			if !strings.Contains(logs.String(), tc.want) {
				t.Errorf("slog output %q lacks %q", logs.String(), tc.want)
			}
			if got := stderr(); got != "" {
				t.Errorf("stderr = %q, want empty", got)
			}
		})
	}
}

func TestNewServeClassifier_CloseErrorLogsDebug(t *testing.T) {
	requireBin(t, "/bin/sh")
	logs := captureSlog(t)
	stderr := captureStderr(t)
	c, closeFn, startFailed := newServeClassifier(config.Config{
		Model: &config.ModelConfig{Command: []string{"/bin/sh", "-c", "exit 3"}},
	})
	if startFailed || c == nil {
		t.Fatalf("c = %v, startFailed = %v, want a classifier", c, startFailed)
	}
	if _, err := c.Classify(context.Background(), pmodel.Input{Hostname: "example.com"}); err == nil {
		t.Fatal("Classify error = nil, want an error from the exited child")
	}
	closeFn()
	const want = `"level":"DEBUG","msg":"policy: model close (non-fatal)","error":"exit status 3"}`
	if !strings.Contains(logs.String(), want) {
		t.Errorf("slog output %q lacks %q", logs.String(), want)
	}
	_ = stderr()
}

// writeEvalModelCfg writes a ward.yaml with the model-less body used by the
// eval tests plus the given model: stanza, and returns its path.
func writeEvalModelCfg(t *testing.T, modelStanza string) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "ward.yaml")
	body := `listen: "127.0.0.1:5354"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
` + modelStanza
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestBuildClassifier_SpawnFailure_HarnessError(t *testing.T) {
	cfg := writeEvalModelCfg(t, "model:\n  command: [\"/nonexistent/ward-test-model\"]\n")
	logs := captureSlog(t)
	stderr := captureStderr(t)
	clf, cleanup, err := buildClassifier(cfg)
	se := asServeError(t, err, 2)
	if !strings.HasPrefix(se.Message, "harness error: model adapter spawn: model: child start: ") {
		t.Errorf("Message = %q, want harness error spawn prefix", se.Message)
	}
	const rem = "verify model.command in ward.yaml points at an executable that speaks the SP10b wire format"
	if se.Remediation != rem {
		t.Errorf("Remediation = %q, want %q", se.Remediation, rem)
	}
	if clf != nil {
		t.Errorf("classifier = %T, want nil", clf)
	}
	if cleanup == nil {
		t.Fatal("cleanup = nil, want non-nil")
	}
	cleanup()
	if got := stderr(); !strings.HasPrefix(got, "eval error\nharness error: model adapter spawn: ") {
		t.Errorf("stderr = %q, want eval error label then harness error", got)
	}
	recs := slogRecords(t, logs.String())
	if len(recs) != 1 {
		t.Fatalf("slog records = %d (%s), want 1", len(recs), logs.String())
	}
	r := recs[0]
	if r["level"] != "ERROR" || r["msg"] != "startup error" || r["label"] != "eval error" ||
		r["error"] != se.Message || r["remediation"] != se.Remediation {
		t.Errorf("record = %v, want ERROR startup error / eval error / message / remediation", r)
	}
}

func TestBuildClassifier_LoadedPathsLogNothing(t *testing.T) {
	cases := []struct {
		name, stanza, bin string
	}{
		{"builtin", "model:\n  builtin: lexical\n", ""},
		{"command", "model:\n  command: [\"/bin/cat\"]\n", "/bin/cat"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.bin != "" {
				requireBin(t, tc.bin)
			}
			cfg := writeEvalModelCfg(t, tc.stanza)
			logs := captureSlog(t)
			stderr := captureStderr(t)
			clf, cleanup, err := buildClassifier(cfg)
			if err != nil {
				t.Fatalf("buildClassifier: %v", err)
			}
			if clf == nil {
				t.Error("classifier = nil, want non-nil")
			}
			cleanup()
			if got := stderr(); got != "" {
				t.Errorf("stderr = %q, want empty", got)
			}
			if got := logs.String(); got != "" {
				t.Errorf("slog output = %q, want empty", got)
			}
		})
	}
}

func TestBuildClassifier_CloseError_NoRecord(t *testing.T) {
	requireBin(t, "/bin/sh")
	cfg := writeEvalModelCfg(t, "model:\n  command: [\"/bin/sh\", \"-c\", \"exit 3\"]\n")
	logs := captureSlog(t)
	clf, cleanup, err := buildClassifier(cfg)
	if err != nil {
		t.Fatalf("buildClassifier: %v", err)
	}
	if _, err := clf.Classify(context.Background(), pmodel.Input{Hostname: "example.com"}); err == nil {
		t.Fatal("Classify error = nil, want an error from the exited child")
	}
	cleanup()
	if got := logs.String(); got != "" {
		t.Errorf("slog output = %q, want empty (eval's closer is silent)", got)
	}
}

func TestEval_ModelLogLines_NotOnStderr(t *testing.T) {
	t.Parallel()
	requireBin(t, "/bin/sh")
	bin, err := buildWardBin()
	if err != nil {
		t.Fatalf("build ward: %v", err)
	}
	cfg := writeEvalModelCfg(t, "model:\n  command: [\"/bin/sh\", \"-c\", \"exit 3\"]\n")
	suite := filepath.Join(t.TempDir(), "suite.jsonl")
	if err := os.WriteFile(suite, []byte(`{"hostname":"example.com","expected_verdict":"benign","label":"x"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "eval", "--config", cfg, "--suite", suite)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(runErr, &ee) || ee.ExitCode() != 2 {
		t.Fatalf("run error = %v, want exit code 2\nstderr: %s", runErr, stderr.String())
	}
	if !strings.Contains(stderr.String(), "harness error: classify record 0") {
		t.Errorf("stderr lacks classify record error: %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "policy: model") {
		t.Errorf("stderr contains a policy: model line: %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}
