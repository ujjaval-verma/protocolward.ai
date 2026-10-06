// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"protocolward.ai/ward/internal/config"
	"protocolward.ai/ward/internal/model"
	"protocolward.ai/ward/pkg/detect"
	pmodel "protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

// labelResult is the per-label tally surfaced in the JSON detail line.
type labelResult struct {
	Records int `json:"records"`
	Correct int `json:"correct"`
}

// evalResult is the accumulator + JSON-serialized summary of one eval run.
type evalResult struct {
	Records   int                    `json:"records"`
	Correct   int                    `json:"correct"`
	Accuracy  float64                `json:"accuracy"`
	Threshold float64                `json:"threshold"`
	ByLabel   map[string]labelResult `json:"by_label"`
	// MaliciousRecall is the share of expected-malicious records the
	// classifier called malicious (0 when the suite has none).
	MaliciousRecall float64 `json:"malicious_recall"`
	// BenignFPR is the share of expected-benign records the classifier
	// called anything other than benign (0 when the suite has none).
	BenignFPR float64 `json:"benign_fpr"`
}

// scoreSuite dispatches each record through the classifier and accumulates
// overall + per-label tallies. Any classifier error aborts the run — the
// eval surface treats an unavailable model as a harness error (exit 2),
// not a regression, because the classifier wasn't actually scored.
func scoreSuite(ctx context.Context, clf pmodel.Classifier, records []evalRecord) (evalResult, error) {
	res := evalResult{ByLabel: make(map[string]labelResult)}
	var malTotal, malHit, benTotal, benFlagged int
	for i, r := range records {
		v, err := clf.Classify(ctx, pmodel.Input{Hostname: r.Hostname})
		if err != nil {
			return evalResult{}, fmt.Errorf("classify record %d (%q): %w", i, r.Hostname, err)
		}
		res.Records++
		lr := res.ByLabel[r.Label]
		lr.Records++
		if v == r.ExpectedVerdict {
			res.Correct++
			lr.Correct++
		}
		res.ByLabel[r.Label] = lr
		switch r.ExpectedVerdict {
		case schema.VerdictMalicious:
			malTotal++
			if v == schema.VerdictMalicious {
				malHit++
			}
		case schema.VerdictBenign:
			benTotal++
			if v != schema.VerdictBenign {
				benFlagged++
			}
		case schema.VerdictTelemetry:
		}
	}
	if res.Records > 0 {
		res.Accuracy = float64(res.Correct) / float64(res.Records)
	}
	if malTotal > 0 {
		res.MaliciousRecall = float64(malHit) / float64(malTotal)
	}
	if benTotal > 0 {
		res.BenignFPR = float64(benFlagged) / float64(benTotal)
	}
	return res, nil
}

// evalOpts holds parsed flags for `ward eval`.
type evalOpts struct {
	ConfigPath string
	SuitePath  string
	Threshold  float64
	// Builtin scores the in-process lexical detector (pkg/detect) instead
	// of the ward.yaml model: sibling. Mutually exclusive with ConfigPath.
	Builtin bool
	// MinRecall gates MaliciousRecall ≥ MinRecall. 0 disables the gate.
	MinRecall float64
	// MaxFPR gates BenignFPR ≤ MaxFPR. 0 disables the gate.
	MaxFPR float64
}

// evalRecord is one JSONL row of the eval suite. Wire form lives in
// testdata/eval/v0.2.jsonl; this struct is authoritative.
type evalRecord struct {
	Hostname        string         `json:"hostname"`
	ExpectedVerdict schema.Verdict `json:"expected_verdict"`
	Label           string         `json:"label"`
}

// loadEvalSuite reads a JSONL fixture from path and decodes one evalRecord
// per non-blank line. Empty fixtures return an empty slice + nil error; the
// "no records" condition is exit-code material and handled by evalRun.
//
// Blank lines (including leading/trailing whitespace) are skipped. Any
// decode error or missing required field (Hostname, Label) is returned
// with the offending line number so operators can locate the bad row.
func loadEvalSuite(path string) ([]evalRecord, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied fixture path
	if err != nil {
		return nil, fmt.Errorf("open suite %q: %w", path, err)
	}
	defer f.Close()

	var records []evalRecord
	scanner := bufio.NewScanner(f)
	// Allow generous line size — JSONL records are small but defensively
	// raise the buffer above the 64KB default.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var r evalRecord
		dec := json.NewDecoder(bytes.NewReader(line))
		// Strict: adding new fixture fields (e.g. client_hints, user_agent
		// in v0.3) requires a corresponding evalRecord struct extension.
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("suite %q line %d: %w", path, lineNum, err)
		}
		if r.Hostname == "" {
			return nil, fmt.Errorf("suite %q line %d: hostname is empty", path, lineNum)
		}
		if r.Label == "" {
			return nil, fmt.Errorf("suite %q line %d: label is empty", path, lineNum)
		}
		records = append(records, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan suite %q: %w", path, err)
	}
	return records, nil
}

// evalRun validates --suite, then either scores the built-in lexical
// detector (--builtin) or builds the classifier from ward.yaml, then
// delegates to evalRunWith. Suite validation runs first so a missing
// --suite or empty-fixture short-circuit doesn't pay the classifier-spawn
// cost.
func evalRun(out io.Writer, opts evalOpts) error {
	if opts.SuitePath == "" {
		msg := "harness error: --suite is required"
		rem := "ward eval --suite <path-to-jsonl-fixture>"
		printStartupError("eval error", msg, rem)
		return &serveError{Code: 2, Message: msg, Remediation: rem}
	}
	if opts.Builtin {
		if opts.ConfigPath != "" {
			msg := "harness error: --builtin and --config are mutually exclusive"
			rem := "drop --config to score the built-in lexical detector, or drop --builtin to score the ward.yaml model"
			printStartupError("eval error", msg, rem)
			return &serveError{Code: 2, Message: msg, Remediation: rem}
		}
		return evalRunWith(out, opts, detect.New())
	}
	clf, cleanup, err := buildClassifier(opts.ConfigPath)
	if err != nil {
		return err
	}
	defer cleanup()
	return evalRunWith(out, opts, clf)
}

// evalRunWith is the testable core. Callers MUST pass a non-empty
// opts.SuitePath — evalRun guards that invariant before delegating;
// direct test callers do too (no production caller bypasses evalRun).
// Loads + validates the suite, scores, applies the threshold gate,
// emits the canonical summary + JSON detail, returns a *serveError
// with the right exit code.
func evalRunWith(out io.Writer, opts evalOpts, clf pmodel.Classifier) error {
	records, err := loadEvalSuite(opts.SuitePath)
	if err != nil {
		msg := fmt.Sprintf("harness error: load suite: %v", err)
		rem := "verify the fixture path + JSONL syntax (one record per line, expected_verdict ∈ {benign,telemetry,malicious})"
		printStartupError("eval error", msg, rem)
		return &serveError{Code: 2, Message: msg, Remediation: rem}
	}
	if len(records) == 0 {
		msg := "harness error: fixture contains no records"
		rem := "add at least one record to the suite (or check for blank-only files)"
		printStartupError("eval error", msg, rem)
		return &serveError{Code: 2, Message: msg, Remediation: rem}
	}

	res, err := scoreSuite(context.Background(), clf, records)
	if err != nil {
		msg := fmt.Sprintf("harness error: %v", err)
		rem := "check the model: stanza in ward.yaml and the model sibling binary"
		if errors.Is(err, detect.ErrInvalidHostname) {
			rem = "fix or remove the fixture record: not a valid DNS hostname"
		}
		printStartupError("eval error", msg, rem)
		return &serveError{Code: 2, Message: msg, Remediation: rem}
	}
	res.Threshold = opts.Threshold

	verdict := "PASS"
	op := "≥"
	if res.Accuracy < opts.Threshold {
		verdict = "FAIL"
		op = "<"
	}
	fmt.Fprintf(out, "ward eval: %d/%d correct (%.2f %s %.2f) — %s\n",
		res.Correct, res.Records, res.Accuracy, op, opts.Threshold, verdict)
	detail, err := json.Marshal(res)
	if err != nil {
		// Unreachable — evalResult has no channels / funcs.
		return &serveError{Code: 2, Message: fmt.Sprintf("harness error: marshal detail: %v", err)}
	}
	fmt.Fprintln(out, string(detail))

	if verdict == "FAIL" {
		return &serveError{Code: 1, Message: fmt.Sprintf("accuracy %.4f below threshold %.4f", res.Accuracy, opts.Threshold)}
	}
	if opts.MinRecall > 0 || opts.MaxFPR > 0 {
		gate := "PASS"
		recallOK := opts.MinRecall <= 0 || res.MaliciousRecall >= opts.MinRecall
		fprOK := opts.MaxFPR <= 0 || res.BenignFPR <= opts.MaxFPR
		if !recallOK || !fprOK {
			gate = "FAIL"
		}
		fmt.Fprintf(out, "ward eval: malicious recall %.3f (min %.2f), benign FPR %.4f (max %.4f) — %s\n",
			res.MaliciousRecall, opts.MinRecall, res.BenignFPR, opts.MaxFPR, gate)
		if gate == "FAIL" {
			return &serveError{Code: 1, Message: fmt.Sprintf("malicious recall %.4f (min %.4f) / benign FPR %.4f (max %.4f) outside gate",
				res.MaliciousRecall, opts.MinRecall, res.BenignFPR, opts.MaxFPR)}
		}
	}
	return nil
}

// buildClassifier resolves the ward.yaml config and constructs the slow-
// path adapter or, for `model.builtin: lexical`, the in-process
// detect.Lexical (no-op cleanup). Returns a *serveError on every failure
// path: missing config, missing model: stanza, adapter spawn failure → exit
// 2. Cleanup closes the adapter (if any); safe to call before the adapter is
// constructed.
//
// context.Background() is passed to model.New so the adapter's lifetime
// is owned solely by Close — same pattern as cmd/ward/serve.go:314 (per
// SP10b Ralph F1).
func buildClassifier(configPath string) (pmodel.Classifier, func(), error) {
	cfgPath, err := resolveConfigPath(configPath)
	if err != nil {
		var se *serveError
		if errors.As(err, &se) {
			printStartupError("config error", se.Message, se.Remediation)
			return nil, func() {}, &serveError{Code: 2, Message: se.Message, Remediation: se.Remediation}
		}
		printStartupError("config error", err.Error(), "")
		return nil, func() {}, &serveError{Code: 2, Message: err.Error()}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, func() {}, mapConfigLoadError(cfgPath, err)
	}
	if cfg.Model == nil {
		msg := "harness error: ward.yaml has no model: stanza — eval needs a configured slow-path classifier"
		rem := "add model: {builtin: lexical} (in-process detector) or a model.command stanza to ward.yaml, or use ward eval --builtin"
		printStartupError("eval error", msg, rem)
		return nil, func() {}, &serveError{Code: 2, Message: msg, Remediation: rem}
	}
	if cfg.Model.Builtin == config.ModelBuiltinLexical {
		return detect.New(), func() {}, nil
	}
	ad, err := model.New(context.Background(), model.Config{
		Command: cfg.Model.Command,
		Env:     cfg.Model.Env,
	})
	if err != nil {
		msg := fmt.Sprintf("harness error: model adapter spawn: %v", err)
		rem := "verify model.command in ward.yaml points at an executable that speaks the SP10b wire format"
		printStartupError("eval error", msg, rem)
		return nil, func() {}, &serveError{Code: 2, Message: msg, Remediation: rem}
	}
	return ad, func() { _ = ad.Close() }, nil
}

func newEvalCmd() *cobra.Command {
	var opts evalOpts
	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Score the configured slow-path classifier against a labelled JSONL fixture",
		Long: `ward eval runs the configured slow-path classifier against every record
in a labelled JSONL fixture and exits 0 if accuracy ≥ --threshold.

Fixture format (one record per line):
  {"hostname":"<qname>","expected_verdict":"benign|telemetry|malicious","label":"<category>"}

Exit codes:
  0  accuracy ≥ threshold (PASS)
  1  accuracy < threshold (FAIL — model regressed)
  2  harness error (fixture parse failure, no model config, classifier init failure)

--builtin scores the in-process lexical DGA detector (pkg/detect) and needs
no ward.yaml. --min-recall / --max-fpr add a second gate on malicious recall
and benign false-positive rate (0 disables each). The lexical acceptance run:
  ward eval --builtin --suite testdata/eval/lexical-v1.jsonl --min-recall 0.85 --max-fpr 0.01`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := evalRun(cmd.OutOrStdout(), opts); err != nil {
				var se *serveError
				if errors.As(err, &se) {
					os.Exit(se.Code)
				}
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.ConfigPath, "config", "", "path to ward.yaml config file")
	cmd.Flags().StringVar(&opts.SuitePath, "suite", "", "path to the labelled JSONL eval fixture (required)")
	cmd.Flags().Float64Var(&opts.Threshold, "threshold", 0.85, "accuracy floor; exit non-zero if overall accuracy is below this")
	cmd.Flags().BoolVar(&opts.Builtin, "builtin", false, "score the built-in lexical detector instead of the ward.yaml model (no config needed)")
	cmd.Flags().Float64Var(&opts.MinRecall, "min-recall", 0, "malicious-recall floor; 0 disables")
	cmd.Flags().Float64Var(&opts.MaxFPR, "max-fpr", 0, "benign false-positive-rate ceiling; 0 disables")
	return cmd
}
