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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"protocolward.ai/ward/internal/model"
	pkgmodel "protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

const fakeChildEnv = "WARD_TEST_FAKE_CLASSIFIER"

// fakeChildPIDFileEnv, when set, names a file the fake child writes its pid
// to before reading any request.
const fakeChildPIDFileEnv = "WARD_TEST_FAKE_CLASSIFIER_PIDFILE"

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
	if path := os.Getenv(fakeChildPIDFileEnv); path != "" {
		_ = os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o600)
	}

	first := true
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			if mode == "ignore-eof" {
				time.Sleep(5 * time.Second) // ignores EOF; bounded so a red run ends
			}
			return
		}
		// Parse the request just enough to extract hostname for "echo" mode.
		var req struct {
			Hostname string `json:"hostname"`
		}
		_ = json.Unmarshal([]byte(strings.TrimRight(line, "\n")), &req)

		switch mode {
		case "benign", "ignore-eof":
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
		case "slow50ms":
			time.Sleep(50 * time.Millisecond)
			emit("benign")
		case "hang-after-read":
			// Took the request, never replies. Exits after 5 s only so a
			// red run (no reply timeout) ends instead of hanging the package.
			time.Sleep(5 * time.Second)
			os.Exit(0)
		default:
			os.Exit(1)
		}
	}
}

// fakeChildConfig builds a Config that re-execs this test binary in fake-
// child mode. `-test.run=^$` ensures no real tests run in the child.
// GORACE atexit_sleep_ms=0 (child only): under -race the child is a race
// binary, which otherwise sleeps 1 s on exit, and Close waits for that
// exit. The caller's other GORACE options are kept; the later
// atexit_sleep_ms wins. The parent test binary's GORACE is not changed.
func fakeChildConfig(_ *testing.T, mode string) model.Config {
	gorace := strings.TrimSpace(os.Getenv("GORACE") + " atexit_sleep_ms=0")
	return model.Config{
		Command: []string{os.Args[0], "-test.run=^$"},
		Env:     append(os.Environ(), fakeChildEnv+"="+mode, "GORACE="+gorace),
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

// TestAdapter_ContextDoneBeforeCall_SkipsWithoutPoison is the T-C row
// (issue #16). A ctx that is already done when Classify is called means
// nothing is written to the child, so the wire protocol is still in step:
// the call returns ErrSkipped (wrapping ctx.Err()), never ErrUnavailable,
// and the next call with a live ctx is answered.
func TestAdapter_ContextDoneBeforeCall_SkipsWithoutPoison(t *testing.T) {
	a, err := model.New(context.Background(), fakeChildConfig(t, "benign"))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	defer func() { _ = a.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// With a free slot and a done ctx, Classify's select picks either case
	// at random. Looping covers the post-acquire ctx check on every run
	// (the chance of missing it in 40 tries is 2^-40).
	for i := range 40 {
		_, err = a.Classify(ctx, pkgmodel.Input{Hostname: "ex.com"})
		if !errors.Is(err, model.ErrSkipped) || !errors.Is(err, context.Canceled) {
			t.Fatalf("call %d: Classify err = %v; want ErrSkipped wrapping context.Canceled", i, err)
		}
		if errors.Is(err, model.ErrUnavailable) {
			t.Fatalf("call %d: Classify err = %v; a ctx that ended before the call must not be ErrUnavailable", i, err)
		}
	}

	got, err := a.Classify(context.Background(), pkgmodel.Input{Hostname: "ex.com"})
	if err != nil || got != schema.VerdictBenign {
		t.Errorf("Classify after skip = (%v, %v); want (VerdictBenign, nil): adapter must stay usable", got, err)
	}
}

// TestAdapter_Burst_WaitersSkipAdapterStaysUsable is the T-B row (issue
// #16): 100 concurrent calls against a 50 ms child with a 300 ms deadline
// each. A few are answered; the rest give up while waiting and return
// ErrSkipped. None is ErrUnavailable and the adapter answers afterwards.
func TestAdapter_Burst_WaitersSkipAdapterStaysUsable(t *testing.T) {
	a, err := model.New(context.Background(), fakeChildConfig(t, "slow50ms"))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	defer func() { _ = a.Close() }()

	const n = 100
	errs := make(chan error, n)
	for range n {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			_, err := a.Classify(ctx, pkgmodel.Input{Hostname: "ex.com"})
			errs <- err
		}()
	}
	ok, skipped, other := 0, 0, 0
	var firstOther error
	for range n {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, model.ErrSkipped) && !errors.Is(err, model.ErrUnavailable):
			skipped++
		default:
			other++
			if firstOther == nil {
				firstOther = err
			}
		}
	}
	if other != 0 || ok == 0 || skipped == 0 {
		t.Errorf("burst: ok=%d skipped=%d other=%d (first: %v); want other=0 and ok, skipped > 0 (100 x 50 ms cannot fit in 300 ms)",
			ok, skipped, other, firstOther)
	}

	got, err := a.Classify(context.Background(), pkgmodel.Input{Hostname: "ex.com"})
	if err != nil || got != schema.VerdictBenign {
		t.Errorf("Classify after burst = (%v, %v); want (VerdictBenign, nil): only child failures may poison", got, err)
	}
}

// classifyWithin runs Classify on its own goroutine and fails the test if
// it has not returned within limit. The limit is a watchdog, not a timing
// assertion: it is many times the configured reply timeout.
func classifyWithin(t *testing.T, a *model.Adapter, ctx context.Context, limit time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := a.Classify(ctx, pkgmodel.Input{Hostname: "ex.com"})
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("Classify did not return within %s: a hung child must not hold the adapter", limit)
		return nil
	}
}

// TestAdapter_HungReply_PoisonsWithinReplyTimeout is the T-H row. The child
// reads the request and never replies. The exchange is bounded by
// ReplyTimeout: Classify returns ErrUnavailable wrapping ErrNoReply, the
// child is killed (the stream is out of step), later calls fail fast, and
// Close returns.
func TestAdapter_HungReply_PoisonsWithinReplyTimeout(t *testing.T) {
	cfg := fakeChildConfig(t, "hang-after-read")
	cfg.ReplyTimeout = 100 * time.Millisecond
	a, err := model.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New = %v", err)
	}

	err = classifyWithin(t, a, context.Background(), 2*time.Second)
	if !errors.Is(err, model.ErrUnavailable) || !errors.Is(err, model.ErrNoReply) {
		t.Errorf("Classify err = %v; want ErrUnavailable wrapping ErrNoReply", err)
	}
	if err := classifyWithin(t, a, context.Background(), 2*time.Second); !errors.Is(err, model.ErrUnavailable) {
		t.Errorf("second Classify err = %v; want ErrUnavailable (poisoned)", err)
	}

	closed := make(chan struct{})
	go func() { _ = a.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return within 2s after a hung reply")
	}
}

// TestAdapter_HungReply_KilledChildReapedBeforeClose is the T-HZ row: the
// child killed on a missed reply is reaped at once, not left a zombie
// (holding a pid and two fds) until Close. Close still returns.
func TestAdapter_HungReply_KilledChildReapedBeforeClose(t *testing.T) {
	pidFile := t.TempDir() + "/child.pid"
	cfg := fakeChildConfig(t, "hang-after-read")
	cfg.Env = append(cfg.Env, fakeChildPIDFileEnv+"="+pidFile)
	cfg.ReplyTimeout = 100 * time.Millisecond
	a, err := model.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	if err := classifyWithin(t, a, context.Background(), 2*time.Second); !errors.Is(err, model.ErrNoReply) {
		t.Fatalf("Classify err = %v; want ErrNoReply", err)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read child pid: %v", err)
	}
	pid, err := strconv.Atoi(string(raw))
	if err != nil {
		t.Fatalf("child pid %q: %v", raw, err)
	}

	// A zombie still answers signal 0; a reaped pid returns ESRCH. The 2 s
	// limit is a watchdog: the reap follows the kill at once.
	deadline := time.Now().Add(2 * time.Second)
	for syscall.Kill(pid, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("signal 0 to the killed child = %v; want ESRCH (reaped before Close)", err)
	}

	closed := make(chan struct{})
	go func() { _ = a.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return within 2s after the child was reaped")
	}
}

// TestAdapter_HungReply_ReleasesWaiters is the T-HW row: a caller queued
// behind the hung exchange gets ErrUnavailable once the reply timeout
// fires, not ErrSkipped after its own (long) deadline.
func TestAdapter_HungReply_ReleasesWaiters(t *testing.T) {
	cfg := fakeChildConfig(t, "hang-after-read")
	cfg.ReplyTimeout = 100 * time.Millisecond
	a, err := model.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	defer func() { _ = a.Close() }()

	errs := make(chan error, 2)
	for range 2 {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := a.Classify(ctx, pkgmodel.Input{Hostname: "ex.com"})
			errs <- err
		}()
	}
	noReply := 0
	for i := range 2 {
		select {
		case err := <-errs:
			if !errors.Is(err, model.ErrUnavailable) || errors.Is(err, model.ErrSkipped) {
				t.Errorf("call %d err = %v; want ErrUnavailable, not ErrSkipped", i, err)
			}
			if errors.Is(err, model.ErrNoReply) {
				noReply++
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("call %d did not return within 3s: the waiter is still wedged", i)
		}
	}
	if noReply == 0 {
		t.Error("no call wrapped ErrNoReply; want the exchange that hit the timeout to say so")
	}
}

// TestAdapter_ShortCtx_ExchangeNotBoundedByCtx is the T-HC row, a guard
// against regressing #16: the exchange is bounded by ReplyTimeout, not by
// the caller's ctx (which in the dataplane also covers the wait for the
// slot). A ctx that ends mid-exchange neither interrupts nor poisons.
func TestAdapter_ShortCtx_ExchangeNotBoundedByCtx(t *testing.T) {
	a, err := model.New(context.Background(), fakeChildConfig(t, "slow50ms"))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	defer func() { _ = a.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	got, err := a.Classify(ctx, pkgmodel.Input{Hostname: "ex.com"})
	if err != nil || got != schema.VerdictBenign {
		t.Fatalf("Classify with a 25ms ctx against a 50ms child = (%v, %v); want (VerdictBenign, nil)", got, err)
	}
	got, err = a.Classify(context.Background(), pkgmodel.Input{Hostname: "ex.com"})
	if err != nil || got != schema.VerdictBenign {
		t.Errorf("next Classify = (%v, %v); want (VerdictBenign, nil): a slow-but-alive child must not be poisoned", got, err)
	}
}

// TestAdapter_ConcurrentClassify is the T-CC row: 32 goroutines call
// Classify concurrently; the one-slot semaphore serializes; no race; all return Benign.
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

// TestAdapter_Close_ChildIgnoresEOF_KilledAfterGrace is the T-CG row: a
// child that does not exit on stdin EOF is killed after CloseGrace, so
// Close (and ward serve shutdown) is bounded.
func TestAdapter_Close_ChildIgnoresEOF_KilledAfterGrace(t *testing.T) {
	cfg := fakeChildConfig(t, "ignore-eof")
	cfg.CloseGrace = 100 * time.Millisecond
	a, err := model.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	if _, err := a.Classify(context.Background(), pkgmodel.Input{Hostname: "ex.com"}); err != nil {
		t.Fatalf("Classify = %v", err)
	}
	closed := make(chan struct{})
	go func() { _ = a.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return within 2s: a child ignoring EOF must be killed after CloseGrace")
	}
}

// TestAdapter_ClassifyAfterClose_SkipsWithoutTouchingChild is the T-AC
// row: after Close, Classify returns ErrSkipped wrapping ErrClosed and
// never writes to the closed stdin, so it is never ErrUnavailable (which
// the dataplane would log as `policy: model unavailable`).
func TestAdapter_ClassifyAfterClose_SkipsWithoutTouchingChild(t *testing.T) {
	a, err := model.New(context.Background(), fakeChildConfig(t, "benign"))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	for i := range 2 {
		_, err := a.Classify(context.Background(), pkgmodel.Input{Hostname: "ex.com"})
		if !errors.Is(err, model.ErrSkipped) || !errors.Is(err, model.ErrClosed) || errors.Is(err, model.ErrUnavailable) {
			t.Errorf("call %d after Close: err = %v; want ErrSkipped wrapping ErrClosed, never ErrUnavailable", i, err)
		}
	}
}

// TestAdapter_New_EmptyCommand_ErrNoCommand is the T-NC row.
func TestAdapter_New_EmptyCommand_ErrNoCommand(t *testing.T) {
	_, err := model.New(context.Background(), model.Config{Command: nil})
	if !errors.Is(err, model.ErrNoCommand) {
		t.Errorf("err = %v; want ErrNoCommand", err)
	}
}
