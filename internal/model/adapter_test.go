// SPDX-License-Identifier: Apache-2.0

package model_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"protocolward.ai/ward/internal/model"
	pkgmodel "protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

const fakeChildEnv = "WARD_TEST_FAKE_CLASSIFIER"

// TestMain re-execs the test binary as the fake classifier child when
// fakeChildEnv is set. This is the standard Go pattern for testing
// subprocess-spawning code without a separate helper binary.
func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeChildEnv); mode != "" {
		runFakeChild(mode) // never returns
	}
	os.Exit(m.Run())
}

// runFakeChild reads newline-delimited JSON requests on stdin and emits
// responses on stdout per the mode. Modes are documented in the spec.
func runFakeChild(mode string) {
	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer func() { _ = out.Flush() }()

	emit := func(v string) {
		_, _ = fmt.Fprintf(out, "{%q:%q}\n", "verdict", v)
		_ = out.Flush()
	}

	if mode == "die-on-start" {
		os.Exit(0)
	}

	first := true
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			return
		}
		// Parse the request just enough to extract hostname for "echo" mode.
		var req struct {
			Hostname string `json:"hostname"`
		}
		_ = json.Unmarshal([]byte(strings.TrimRight(line, "\n")), &req)

		switch mode {
		case "benign":
			emit("benign")
		case "echo":
			switch req.Hostname {
			case "telemetry.test":
				emit("telemetry")
			case "malicious.test":
				emit("malicious")
			default:
				emit("benign")
			}
		case "garbage":
			emit("not-a-verdict")
		case "die-first":
			if first {
				first = false
				emit("benign")
				continue
			}
			os.Exit(0)
		case "slow":
			time.Sleep(2 * time.Second)
			emit("benign")
		default:
			os.Exit(1)
		}
	}
}

// fakeChildConfig builds a Config that re-execs this test binary in fake-
// child mode. `-test.run=^$` ensures no real tests run in the child.
func fakeChildConfig(_ *testing.T, mode string) model.Config {
	return model.Config{
		Command: []string{os.Args[0], "-test.run=^$"},
		Env:     append(os.Environ(), fakeChildEnv+"="+mode),
	}
}

// TestAdapter_TracerBullet_BenignRoundTrip is the T-AR row from the spec.
// Stands up the subprocess harness on the simplest path: spawn → classify
// → close. Proves Config / New / Classify / Close are wired end-to-end.
func TestAdapter_TracerBullet_BenignRoundTrip(t *testing.T) {
	a, err := model.New(context.Background(), fakeChildConfig(t, "benign"))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	defer func() {
		if err := a.Close(); err != nil {
			t.Errorf("Close = %v", err)
		}
	}()

	got, err := a.Classify(context.Background(), pkgmodel.Input{Hostname: "example.com"})
	if err != nil {
		t.Fatalf("Classify = %v", err)
	}
	if got != schema.VerdictBenign {
		t.Errorf("Classify = %v, want VerdictBenign", got)
	}
}

// Compile-time assertion: *Adapter satisfies pkg/model.Classifier.
// Lives in the test file so the dependency direction stays one-way.
var _ pkgmodel.Classifier = (*model.Adapter)(nil)

// silence unused-import warnings if a future cycle removes one of these.
var (
	_ = io.EOF
	_ = errors.New
)

// TestAdapter_EveryVerdictVariant is the T-V row: echo-mode hostnames map
// to each Verdict variant, proving the schema.Verdict UnmarshalJSON wire
// path round-trips for all defined values.
func TestAdapter_EveryVerdictVariant(t *testing.T) {
	tests := []struct {
		hostname string
		want     schema.Verdict
	}{
		{"benign.test", schema.VerdictBenign},
		{"telemetry.test", schema.VerdictTelemetry},
		{"malicious.test", schema.VerdictMalicious},
		{"unknown-host.test", schema.VerdictBenign}, // unrecognized → benign fallback
	}
	a, err := model.New(context.Background(), fakeChildConfig(t, "echo"))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	defer func() { _ = a.Close() }()

	for _, tc := range tests {
		t.Run(tc.hostname, func(t *testing.T) {
			got, err := a.Classify(context.Background(), pkgmodel.Input{Hostname: tc.hostname})
			if err != nil {
				t.Fatalf("Classify(%s) = %v", tc.hostname, err)
			}
			if got != tc.want {
				t.Errorf("Classify(%s) = %v, want %v", tc.hostname, got, tc.want)
			}
		})
	}
}

// TestAdapter_MalformedVerdict_PoisonsAndReturnsUnavailable is the T-U
// row: a child that emits an unknown verdict string is treated as
// unavailable; subsequent Classify calls short-circuit.
func TestAdapter_MalformedVerdict_PoisonsAndReturnsUnavailable(t *testing.T) {
	a, err := model.New(context.Background(), fakeChildConfig(t, "garbage"))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	defer func() { _ = a.Close() }()

	_, err = a.Classify(context.Background(), pkgmodel.Input{Hostname: "ex.com"})
	if err == nil {
		t.Fatal("Classify returned nil err on garbage response; want error")
	}
	if !errors.Is(err, model.ErrUnavailable) {
		t.Errorf("err = %v; want errors.Is(err, ErrUnavailable)", err)
	}

	// Second call must short-circuit (no IO; child may be alive but adapter
	// is poisoned).
	_, err2 := a.Classify(context.Background(), pkgmodel.Input{Hostname: "ex.com"})
	if !errors.Is(err2, model.ErrUnavailable) {
		t.Errorf("second Classify err = %v; want ErrUnavailable", err2)
	}
}

// TestAdapter_ChildDiesMidStream_NextClassifyUnavailable is the T-D row:
// one good response, then EOF. Second Classify sees the child gone.
func TestAdapter_ChildDiesMidStream_NextClassifyUnavailable(t *testing.T) {
	a, err := model.New(context.Background(), fakeChildConfig(t, "die-first"))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	defer func() { _ = a.Close() }()

	if got, err := a.Classify(context.Background(), pkgmodel.Input{Hostname: "ex.com"}); err != nil {
		t.Fatalf("first Classify = %v", err)
	} else if got != schema.VerdictBenign {
		t.Fatalf("first Classify = %v, want VerdictBenign", got)
	}

	_, err = a.Classify(context.Background(), pkgmodel.Input{Hostname: "ex.com"})
	if !errors.Is(err, model.ErrUnavailable) {
		t.Errorf("second Classify err = %v; want ErrUnavailable", err)
	}
}

// TestAdapter_ChildDiesOnStart_FirstClassifyUnavailable is the T-D2 row.
// The child exits immediately; the parent's first stdout read sees EOF
// (or the write fails with EPIPE — both wrap ErrUnavailable). The
// behavioural guarantee is independent of when the child died relative
// to cmd.Start returning.
func TestAdapter_ChildDiesOnStart_FirstClassifyUnavailable(t *testing.T) {
	a, err := model.New(context.Background(), fakeChildConfig(t, "die-on-start"))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	defer func() { _ = a.Close() }()

	_, err = a.Classify(context.Background(), pkgmodel.Input{Hostname: "ex.com"})
	if !errors.Is(err, model.ErrUnavailable) {
		t.Errorf("Classify err = %v; want ErrUnavailable", err)
	}
}

// TestAdapter_ContextCancel_PoisonsAdapter is the T-C row: an already-
// cancelled ctx hits the ctx.Err() early-return guard inside Classify;
// the slow child is never read. The mid-read cancel path (where
// exec.CommandContext's background goroutine SIGKILLs the child while
// ReadBytes is blocked) is also exercised compositionally — any IO
// failure surfaces as ErrUnavailable — but is not specifically asserted
// here; SP10c MAY add a dedicated mid-read cancel test when it wires the
// dataplane fork.
func TestAdapter_ContextCancel_PoisonsAdapter(t *testing.T) {
	a, err := model.New(context.Background(), fakeChildConfig(t, "slow"))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	defer func() { _ = a.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already-cancelled ctx — Classify must surface immediately

	_, err = a.Classify(ctx, pkgmodel.Input{Hostname: "ex.com"})
	if !errors.Is(err, model.ErrUnavailable) {
		t.Errorf("Classify err = %v; want ErrUnavailable wrapping ctx err", err)
	}

	// Subsequent Classify with a fresh ctx still short-circuits — adapter
	// is poisoned.
	_, err = a.Classify(context.Background(), pkgmodel.Input{Hostname: "ex.com"})
	if !errors.Is(err, model.ErrUnavailable) {
		t.Errorf("subsequent Classify err = %v; want ErrUnavailable", err)
	}
}

// TestAdapter_ConcurrentClassify is the T-CC row: 32 goroutines call
// Classify concurrently; mutex serializes; no race; all return Benign.
// Run with -race in make ci.
func TestAdapter_ConcurrentClassify(t *testing.T) {
	a, err := model.New(context.Background(), fakeChildConfig(t, "benign"))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	defer func() { _ = a.Close() }()

	const N = 32
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			got, err := a.Classify(context.Background(), pkgmodel.Input{Hostname: "ex.com"})
			if err != nil {
				errs <- err
				return
			}
			if got != schema.VerdictBenign {
				errs <- fmt.Errorf("got %v, want Benign", got)
				return
			}
			errs <- nil
		}()
	}
	for i := 0; i < N; i++ {
		if err := <-errs; err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}

// TestAdapter_Close_Idempotent — Ralph N1 regression coverage. A second
// Close call returns nil (the first reaped the child); not an error.
func TestAdapter_Close_Idempotent(t *testing.T) {
	a, err := model.New(context.Background(), fakeChildConfig(t, "benign"))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("first Close = %v, want nil (clean child exit)", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("second Close = %v, want nil (idempotent)", err)
	}
}

// TestAdapter_New_EmptyCommand_ErrNoCommand is the T-NC row.
func TestAdapter_New_EmptyCommand_ErrNoCommand(t *testing.T) {
	_, err := model.New(context.Background(), model.Config{Command: nil})
	if !errors.Is(err, model.ErrNoCommand) {
		t.Errorf("err = %v; want ErrNoCommand", err)
	}
}
