// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	adapter "protocolward.ai/ward/internal/model"
	"protocolward.ai/ward/internal/obs"
	"protocolward.ai/ward/pkg/detect"
	"protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

// blockingClassifier holds every Classify call until release is closed and
// records how many calls are in Classify at once.
type blockingClassifier struct {
	release chan struct{}
	entered atomic.Int64
	current atomic.Int64
	maxSeen atomic.Int64
}

func (b *blockingClassifier) Classify(_ context.Context, _ model.Input) (schema.Verdict, error) {
	b.entered.Add(1)
	n := b.current.Add(1)
	for {
		m := b.maxSeen.Load()
		if n <= m || b.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	<-b.release
	b.current.Add(-1)
	return schema.VerdictBenign, nil
}

// newBoundTestServer builds a Server whose forward path answers in-process;
// tests call handleQuery directly, so no socket is bound.
func newBoundTestServer(t *testing.T, c SlowPathClassifier) *Server {
	t.Helper()
	srv, err := NewServer(Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []Resolver{&stubResolver{}},
		QueryTimeout:    time.Second,
		ShutdownTimeout: time.Second,
		Classifier:      c,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func forwardOnce(srv *Server, i int) {
	req := new(dns.Msg)
	req.SetQuestion(fmt.Sprintf("burst%d.example.com.", i), dns.TypeA)
	w := &stubResponseWriter{remoteAddr: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 5353}}
	srv.handleQuery(w, req)
}

func countDropLines(records []map[string]any) (n int, last map[string]any) {
	for _, r := range records {
		if r["msg"] == "policy: classify dropped" {
			n++
			last = r
		}
	}
	return n, last
}

// T-BOUND: a burst of 100 forwarded queries never runs more than
// maxClassifyInFlight classifications at once; the rest are dropped,
// counted, and reported by one rate-limited WARN line. Slots are returned.
func TestClassify_Burst_InFlightBounded_DropsCounted(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	bc := &blockingClassifier{release: make(chan struct{})}
	srv := newBoundTestServer(t, bc)
	released := false
	defer func() {
		if !released {
			close(bc.release)
		}
		srv.inFlight.Wait()
	}()

	const burst = 100
	var wg sync.WaitGroup
	for i := range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			forwardOnce(srv, i)
		}()
	}
	wg.Wait() // every admit-or-drop decision has been made

	deadline := time.Now().Add(5 * time.Second)
	for bc.entered.Load()+int64(srv.classifyDropped.Load()) < burst && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bc.entered.Load(); got != maxClassifyInFlight {
		t.Errorf("classify calls started = %d; want %d (maxClassifyInFlight)", got, maxClassifyInFlight)
	}
	if got := bc.maxSeen.Load(); got > maxClassifyInFlight {
		t.Errorf("concurrent classify calls peaked at %d; want <= %d", got, maxClassifyInFlight)
	}
	if got := srv.classifyDropped.Load(); got != burst-maxClassifyInFlight {
		t.Errorf("classifyDropped = %d; want %d", got, burst-maxClassifyInFlight)
	}

	n, rec := countDropLines(obs.Captured(t))
	if n != 1 {
		t.Fatalf("policy: classify dropped lines = %d; want exactly 1 (rate-limited)", n)
	}
	if rec["level"] != "WARN" {
		t.Errorf("level = %v; want WARN", rec["level"])
	}
	if rec["reason"] != "slow path at capacity" {
		t.Errorf("reason = %v; want %q", rec["reason"], "slow path at capacity")
	}
	if _, ok := rec["remediation"]; !ok {
		t.Error("policy: classify dropped has no remediation field (invariant 8)")
	}
	if _, ok := rec["dropped_total"]; !ok {
		t.Error("policy: classify dropped has no dropped_total field")
	}

	// Slots come back: after the blocked calls finish, a new forward is
	// classified, not dropped.
	close(bc.release)
	released = true
	srv.inFlight.Wait()
	forwardOnce(srv, burst)
	srv.inFlight.Wait()
	if got := bc.entered.Load(); got != maxClassifyInFlight+1 {
		t.Errorf("classify calls after release = %d; want %d (slot reused)", got, maxClassifyInFlight+1)
	}
	if got := srv.classifyDropped.Load(); got != burst-maxClassifyInFlight {
		t.Errorf("classifyDropped after release = %d; want unchanged %d", got, burst-maxClassifyInFlight)
	}
}

// T-RATE: the drop line is emitted on the first drop, then at most once per
// classifyDropLogEvery, and always carries the running total.
func TestNoteClassifyDropped_RateLimitedWithRunningTotal(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	srv := newBoundTestServer(t, &blockingClassifier{release: make(chan struct{})})

	for range 3 {
		srv.noteClassifyDropped("a.example.com", "slow path at capacity")
	}
	if n, rec := countDropLines(obs.Captured(t)); n != 1 || rec["dropped_total"] != float64(1) {
		t.Fatalf("after 3 drops: lines = %d, dropped_total = %v; want 1 line with dropped_total 1", n, rec["dropped_total"])
	}

	// Pretend the last line is older than the interval.
	srv.classifyDropLoggedAt.Store(time.Now().Add(-2 * classifyDropLogEvery).UnixNano())
	srv.noteClassifyDropped("b.example.com", "slow path at capacity")
	if n, rec := countDropLines(obs.Captured(t)); n != 2 || rec["dropped_total"] != float64(4) {
		t.Fatalf("after interval: lines = %d, dropped_total = %v; want 2 lines, last dropped_total 4", n, rec["dropped_total"])
	}
	if got := srv.classifyDropped.Load(); got != 4 {
		t.Errorf("classifyDropped = %d; want 4", got)
	}

	// A wall clock that stepped back must not silence the line.
	srv.classifyDropLoggedAt.Store(time.Now().Add(time.Hour).UnixNano())
	srv.noteClassifyDropped("c.example.com", "slow path at capacity")
	if n, rec := countDropLines(obs.Captured(t)); n != 3 || rec["dropped_total"] != float64(5) {
		t.Fatalf("after clock step back: lines = %d, dropped_total = %v; want 3 lines, last dropped_total 5", n, rec["dropped_total"])
	}
}

// panickingClassifier panics on every call (the in-process detector has no
// process boundary; classifyAsync recovers).
type panickingClassifier struct{ calls atomic.Int64 }

func (p *panickingClassifier) Classify(context.Context, model.Input) (schema.Verdict, error) {
	p.calls.Add(1)
	panic("detector bug")
}

// T-PANIC: a recovered classifier panic still returns its slot, so panics
// cannot leak capacity until every forward is dropped.
func TestClassify_PanicReleasesSlot(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	pc := &panickingClassifier{}
	srv := newBoundTestServer(t, pc)

	const n = maxClassifyInFlight + 1
	for i := range n {
		forwardOnce(srv, i)
		srv.inFlight.Wait()
	}
	if got := pc.calls.Load(); got != n {
		t.Errorf("classify calls = %d; want %d (a panic must release its slot)", got, n)
	}
	if got := srv.classifyDropped.Load(); got != 0 {
		t.Errorf("classifyDropped = %d; want 0", got)
	}
}

// skippingClassifier returns what internal/model.Adapter returns when the
// per-call timeout ends while an earlier call holds the child.
type skippingClassifier struct{ calls atomic.Int64 }

func (s *skippingClassifier) Classify(context.Context, model.Input) (schema.Verdict, error) {
	s.calls.Add(1)
	return 0, fmt.Errorf("%w: %w", adapter.ErrSkipped, context.DeadlineExceeded)
}

// T-SKIP: ErrSkipped is a drop, not a failure: counted, one rate-limited
// line, no per-call `policy: classify error`, and no unavailable latch, so
// later forwards are still classified.
func TestClassify_ErrSkipped_CountedNoLatchNoWarnFlood(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	sc := &skippingClassifier{}
	srv := newBoundTestServer(t, sc)

	const n = 5
	for i := range n {
		forwardOnce(srv, i)
		srv.inFlight.Wait() // sequential: never at capacity
	}

	if got := sc.calls.Load(); got != n {
		t.Errorf("classify calls = %d; want %d (ErrSkipped must not latch)", got, n)
	}
	if srv.classifierDead.Load() {
		t.Error("classifierDead latched on ErrSkipped; only ErrUnavailable may latch")
	}
	if got := srv.classifyDropped.Load(); got != n {
		t.Errorf("classifyDropped = %d; want %d", got, n)
	}
	records := obs.Captured(t)
	for _, r := range records {
		if r["msg"] == "policy: classify error" || r["msg"] == "policy: model unavailable" {
			t.Errorf("unexpected %q line for ErrSkipped: %v", r["msg"], r)
		}
	}
	lines, rec := countDropLines(records)
	if lines != 1 {
		t.Fatalf("policy: classify dropped lines = %d; want 1", lines)
	}
	if rec["reason"] != "classifier busy past the classify timeout" {
		t.Errorf("reason = %v; want %q", rec["reason"], "classifier busy past the classify timeout")
	}
}

// serialClassifier mimics internal/model.Adapter: one call at a time, a call
// waiting for its turn honours ctx and returns ErrSkipped, a call that has
// the turn runs for the full dur.
type serialClassifier struct {
	sem     chan struct{}
	dur     time.Duration
	started atomic.Int64
}

func newSerialClassifier(dur time.Duration) *serialClassifier {
	return &serialClassifier{sem: make(chan struct{}, 1), dur: dur}
}

func (s *serialClassifier) Classify(ctx context.Context, _ model.Input) (schema.Verdict, error) {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return 0, fmt.Errorf("%w: %w", adapter.ErrSkipped, ctx.Err())
	}
	defer func() { <-s.sem }()
	s.started.Add(1)
	time.Sleep(s.dur)
	return schema.VerdictBenign, nil
}

// T-SHUTDOWN: Shutdown cancels classifications still waiting for the
// adapter, so the drain takes one call, not one per waiter. Skips caused by
// shutdown are counted but do not produce the drop WARN.
func TestShutdown_CancelsQueuedClassifications(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	const (
		waiters = 8
		callDur = 300 * time.Millisecond
	)
	sc := newSerialClassifier(callDur)
	srv := newBoundTestServer(t, sc)
	srv.cfg.ClassifyTimeout = 30 * time.Second

	for i := range waiters {
		forwardOnce(srv, i)
	}
	deadline := time.Now().Add(5 * time.Second)
	for sc.started.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_ = srv.Shutdown(ctx) // listeners were never bound; the drain is what matters
	elapsed := time.Since(start)

	if limit := 3 * callDur; elapsed > limit {
		t.Errorf("Shutdown took %v; want < %v (queued classifications must be cancelled, not run: %d x %v)", elapsed, limit, waiters, callDur)
	}
	if got := sc.started.Load(); got > 2 {
		t.Errorf("classifications that ran = %d; want at most 2", got)
	}
	if got := srv.classifyDropped.Load(); got < waiters-2 {
		t.Errorf("classifyDropped = %d; want >= %d (shutdown skips are counted)", got, waiters-2)
	}
	if n, _ := countDropLines(obs.Captured(t)); n != 0 {
		t.Errorf("policy: classify dropped lines = %d; want 0 (a shutdown skip is expected, not a warning)", n)
	}
	_ = srv.Shutdown(ctx) // cancelling twice is safe
}

// A classification that starts after Shutdown is skipped at once.
func TestShutdown_ClassifyAfterStopIsSkipped(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	sc := newSerialClassifier(time.Millisecond)
	srv := newBoundTestServer(t, sc)
	_ = srv.Shutdown(context.Background())
	_ = srv.Shutdown(context.Background())
	forwardOnce(srv, 0)
	srv.inFlight.Wait()
	// With a free slot select may pick either case; both are fine, but a
	// drop must never warn.
	if n, _ := countDropLines(obs.Captured(t)); n != 0 {
		t.Errorf("policy: classify dropped lines = %d; want 0", n)
	}
}

// T-RATE-DEBUG: a drop suppressed by the rate limit is still named at Debug.
func TestNoteClassifyDropped_SuppressedDropLoggedAtDebug(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	srv := newBoundTestServer(t, &blockingClassifier{release: make(chan struct{})})
	srv.noteClassifyDropped("a.example.com", "slow path at capacity")
	srv.noteClassifyDropped("quiet.example.com", "slow path at capacity")
	for _, r := range obs.Captured(t) {
		if r["msg"] == "policy: classify drop not logged" && r["level"] == "DEBUG" && r["qname"] == "quiet.example.com" {
			return
		}
	}
	t.Error("no Debug `policy: classify drop not logged` line naming the suppressed qname")
}

// lateAssessor stands for a classify fork that was scheduled before
// Shutdown but has not reached Assess yet: it holds until the stop context
// is cancelled, then runs the real lexical detector with the ctx it got.
type lateAssessor struct {
	srv     *Server
	real    *detect.Lexical
	ctxDone atomic.Bool // the ctx Assess received was already done
}

func (l *lateAssessor) Classify(ctx context.Context, in model.Input) (schema.Verdict, error) {
	return l.real.Classify(ctx, in)
}

func (l *lateAssessor) Assess(ctx context.Context, in model.Input) (schema.Assessment, error) {
	<-l.srv.stopCtx.Done()
	l.ctxDone.Store(ctx.Err() != nil)
	return l.real.Assess(ctx, in)
}

type countingFlags struct {
	mu sync.Mutex
	n  int
}

func (c *countingFlags) RecordFlag(string, string, float64, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
}

// T-DRAIN (issue #46): Shutdown cancels only calls waiting for the
// external classifier. An in-process (Assessor) classification already
// forked runs to completion and records its flag; it never logs a
// classify error.
func TestShutdown_DrainsForkedBuiltinClassification(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	la := &lateAssessor{real: detect.New()}
	flags := &countingFlags{}
	srv, err := NewServer(Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []Resolver{&stubResolver{}},
		QueryTimeout:    time.Second,
		ShutdownTimeout: 2 * time.Second,
		Classifier:      la,
		Flags:           flags,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	la.srv = srv

	req := new(dns.Msg)
	req.SetQuestion("3f9a1c7e5b2d8046af1e9c3b7d5a2e80.info.", dns.TypeA)
	srv.handleQuery(&stubResponseWriter{remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}}, req)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx) // listeners were never bound; the drain is what matters

	if la.ctxDone.Load() {
		t.Error("Assess got a cancelled ctx; a built-in classification must not inherit Shutdown's cancel")
	}
	flags.mu.Lock()
	n := flags.n
	flags.mu.Unlock()
	if n != 1 {
		t.Fatalf("flags = %d, want 1: a fork started before Shutdown must be drained, not cancelled", n)
	}
	for _, r := range obs.Captured(t) {
		if r["msg"] == "policy: classify error" {
			t.Errorf("unexpected policy: classify error on a clean shutdown: %v", r)
		}
	}
}

// The Shutdown split keys on model.Assessor: only a Classify-only
// classifier (the external adapter) is cancelled by Shutdown. If the
// adapter ever gained Assess it would silently lose that cancellation.
func TestAdapter_StaysClassifyOnly(t *testing.T) {
	if _, ok := any((*adapter.Adapter)(nil)).(model.Assessor); ok {
		t.Fatal("internal/model.Adapter must stay Classify-only: Shutdown cancels only the Classify branch (#45/#46)")
	}
}
