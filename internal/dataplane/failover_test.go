// SPDX-License-Identifier: Apache-2.0

package dataplane_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/dataplane"
	"protocolward.ai/ward/internal/obs"
)

// failoverBudget is the QueryTimeout used by the failover tests. It is long
// enough that scheduler noise under -race is small next to it, and short
// enough to keep each test near a second.
const failoverBudget = 1 * time.Second

// failoverSlack is the allowance on top of a wall-clock bound. It stays
// under failoverBudget, so a per-attempt deadline (worst case 2 x budget)
// still fails the bound.
const failoverSlack = 800 * time.Millisecond

// hangingResolver returns a fake that blocks until ctx is done. The channel
// is closed at cleanup so nothing can outlive the test.
func hangingResolver(t *testing.T, addr string) *fakeResolver {
	t.Helper()
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	return &fakeResolver{addr: addr, rcode: dns.RcodeSuccess, hangCh: hang}
}

// failingResolver returns err at once. It reads neither ctx nor the clock,
// so a fast failure is never reported as a timeout.
type failingResolver struct {
	addr string
	err  error
}

func (f *failingResolver) Query(context.Context, *dns.Msg) (*dns.Msg, error) { return nil, f.err }
func (f *failingResolver) Address() string                                   { return f.addr }

// instantResolver answers NOERROR at once. It reads neither ctx nor the
// clock, so whether it answers never depends on scheduling.
type instantResolver struct {
	addr    string
	queries atomic.Int64
}

func (r *instantResolver) Query(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	r.queries.Add(1)
	resp := new(dns.Msg)
	resp.SetReply(req)
	return resp, nil
}

func (r *instantResolver) Address() string { return r.addr }

// deadlineRecorder wraps a Resolver and records the deadline of the context
// of its last Query call before delegating.
type deadlineRecorder struct {
	dataplane.Resolver
	mu       sync.Mutex
	deadline time.Time
	ok       bool
	called   bool
}

func recordDeadline(r dataplane.Resolver) *deadlineRecorder {
	return &deadlineRecorder{Resolver: r}
}

func (d *deadlineRecorder) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	d.mu.Lock()
	d.deadline, d.ok = ctx.Deadline()
	d.called = true
	d.mu.Unlock()
	return d.Resolver.Query(ctx, req)
}

// deadlineOf returns the recorded deadline. It fails the test if Query was
// never called or its ctx had no deadline.
func (d *deadlineRecorder) deadlineOf(t *testing.T) time.Time {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.called {
		t.Fatalf("resolver %s was never queried", d.Address())
	}
	if !d.ok {
		t.Fatalf("resolver %s was queried with no deadline", d.Address())
	}
	return d.deadline
}

// exchangeTimed sends one A query to addr and returns the response and the
// client-side elapsed time. The client timeout is far above every budget
// here, so a slow server shows up as a failed bound, not a client error.
func exchangeTimed(t *testing.T, addr, qname string) (*dns.Msg, time.Duration) {
	t.Helper()
	c := &dns.Client{Timeout: 5 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	start := time.Now()
	resp, _, err := c.Exchange(msg, addr)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("exchange %s: %v (after %s)", qname, err, elapsed)
	}
	return resp, elapsed
}

func TestFakeResolver_HangHonoursContext(t *testing.T) {
	t.Parallel()
	r := hangingResolver(t, "10.0.0.1:853")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := r.Query(ctx, new(dns.Msg))
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Query error = %v; want context.DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hanging fake ignored ctx: Query still blocked 2s after a 20ms deadline")
	}
}

func TestFakeResolver_DoneContextFailsAtOnce(t *testing.T) {
	t.Parallel()
	r := &fakeResolver{addr: "10.0.0.2:853", rcode: dns.RcodeSuccess}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Query(ctx, new(dns.Msg)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Query on a done ctx: error = %v; want context.Canceled", err)
	}
}

// Worst case: both upstreams hang. SERVFAIL must come at about one budget,
// not one budget per attempt (timeouts.query is the end-to-end budget).
func TestServer_BothUpstreamsHang_ServfailWithinBudget(t *testing.T) {
	t.Parallel()
	a := hangingResolver(t, "10.0.0.1:853")
	b := hangingResolver(t, "10.0.0.2:853")
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{a, b},
		QueryTimeout:    failoverBudget,
		ShutdownTimeout: 2 * time.Second,
	})

	resp, elapsed := exchangeTimed(t, addr, "hang2.example.com.")
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s; want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	if elapsed >= failoverBudget+failoverSlack {
		t.Errorf("SERVFAIL after %s; want about one budget %s (+%s slack), not one per attempt", elapsed, failoverBudget, failoverSlack)
	}
}

// The fallback runs on the end-to-end deadline, so a fast primary failure
// leaves it the whole remaining budget, not a fixed half (asserted on the
// deadline it is handed).
func TestServer_PrimaryFailsFast_FallbackGetsRemainingBudget(t *testing.T) {
	t.Parallel()
	primary := &fakeResolver{addr: "10.0.0.1:853", err: errors.New("connection refused")}
	fallback := recordDeadline(&instantResolver{addr: "10.0.0.2:853"})
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{primary, fallback},
		QueryTimeout:    failoverBudget,
		ShutdownTimeout: 2 * time.Second,
	})

	sent := time.Now()
	resp, _ := exchangeTimed(t, addr, "slowfallback.example.com.")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s; want NOERROR from the fallback", dns.RcodeToString[resp.Rcode])
	}
	if got := fallback.deadlineOf(t).Sub(sent); got < failoverBudget {
		t.Errorf("fallback deadline = sent + %s; want at least the whole budget %s (the end-to-end deadline)", got, failoverBudget)
	}
}

// With one resolver there is nothing to fail over to, so its single attempt
// keeps the whole budget (asserted on the deadline it is handed).
func TestServer_SingleResolver_KeepsWholeBudget(t *testing.T) {
	t.Parallel()
	only := recordDeadline(&instantResolver{addr: "10.0.0.1:853"})
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{only},
		QueryTimeout:    failoverBudget,
		ShutdownTimeout: 2 * time.Second,
	})

	sent := time.Now()
	resp, _ := exchangeTimed(t, addr, "single.example.com.")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s; want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if got := only.deadlineOf(t).Sub(sent); got < failoverBudget {
		t.Errorf("single resolver deadline = sent + %s; want at least the whole budget %s", got, failoverBudget)
	}
}

// Issue #15: the primary hangs, the fallback is healthy. The fallback must
// answer, inside the configured budget, and run on the end-to-end deadline.
func TestServer_PrimaryHangs_FallbackAnswersWithinBudget(t *testing.T) {
	t.Parallel()
	primary := hangingResolver(t, "10.0.0.1:853")
	inst := &instantResolver{addr: "10.0.0.2:853"}
	fb := recordDeadline(inst)
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{primary, fb},
		CounterSeed:     0,
		QueryTimeout:    failoverBudget,
		ShutdownTimeout: 2 * time.Second,
	})

	sent := time.Now()
	resp, elapsed := exchangeTimed(t, addr, "hang.example.com.")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s after %s; want NOERROR from the fallback", dns.RcodeToString[resp.Rcode], elapsed)
	}
	if got := fb.deadlineOf(t).Sub(sent); got < failoverBudget {
		t.Errorf("fallback deadline = sent + %s; want at least the whole budget %s (the end-to-end deadline)", got, failoverBudget)
	}
	if got := primary.queries.Load(); got != 1 {
		t.Errorf("primary attempts = %d; want 1", got)
	}
	if got := inst.queries.Load(); got != 1 {
		t.Errorf("fallback attempts = %d; want 1", got)
	}
	if elapsed >= failoverBudget+failoverSlack {
		t.Errorf("answered after %s; want under budget %s (+%s slack)", elapsed, failoverBudget, failoverSlack)
	}
}

// The primary hangs. Its deadline leaves at least 30% of the budget to the
// fallback (asserted on the deadlines), so a primary cap above 70% fails
// (guards the query/2 split). The fallback runs on the end-to-end deadline,
// so the gap is at most half the budget: a fallback with a fresh budget fails.
func TestServer_PrimaryHangs_FallbackNeedingThirtyPercentAnswers(t *testing.T) {
	t.Parallel()
	primary := recordDeadline(hangingResolver(t, "10.0.0.1:853"))
	fallback := recordDeadline(&instantResolver{addr: "10.0.0.2:853"})
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{primary, fallback},
		CounterSeed:     0,
		QueryTimeout:    failoverBudget,
		ShutdownTimeout: 2 * time.Second,
	})

	resp, elapsed := exchangeTimed(t, addr, "slowfallback2.example.com.")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s after %s; want NOERROR from the fallback", dns.RcodeToString[resp.Rcode], elapsed)
	}
	gap := fallback.deadlineOf(t).Sub(primary.deadlineOf(t))
	if gap < failoverBudget*3/10 || gap > failoverBudget/2 {
		t.Errorf("fallback deadline - primary deadline = %s; want between %s (30%% of the budget) and %s (half)", gap, failoverBudget*3/10, failoverBudget/2)
	}
}

// runLoggedQuery serves one A query through resolvers with slog captured,
// drains the handler via Shutdown, and returns the response and records.
// It replaces slog.Default, so callers must not be parallel.
func runLoggedQuery(t *testing.T, resolvers []dataplane.Resolver, qname string) (*dns.Msg, []map[string]any) {
	t.Helper()
	restore := obs.Capture(t)
	defer restore()
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       resolvers,
		CounterSeed:     0,
		QueryTimeout:    failoverBudget,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := exchangeTimed(t, addr, qname)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	return resp, obs.Captured(t)
}

func findRecord(records []map[string]any, level, msgPart string) map[string]any {
	for _, r := range records {
		if r["level"] == level {
			if m, _ := r["msg"].(string); strings.Contains(m, msgPart) {
				return r
			}
		}
	}
	return nil
}

// A rescued query must not hide the dead primary: a WARN names it, says
// whether it timed out, and carries a remediation.
// Serial: runLoggedQuery swaps slog.Default through obs.Capture to assert on log records.
func TestServer_PrimaryHangs_FallbackAnswers_WarnsAboutPrimary(t *testing.T) {
	primary := hangingResolver(t, "10.0.0.1:853")
	fallback := &instantResolver{addr: "10.0.0.2:853"}
	resp, records := runLoggedQuery(t, []dataplane.Resolver{primary, fallback}, "warn.example.com.")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s; want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	rec := findRecord(records, "WARN", "upstream attempt failed")
	if rec == nil {
		t.Fatalf("no WARN record for the failed primary attempt; records: %v", records)
	}
	if rec["upstream"] != "10.0.0.1:853" {
		t.Errorf("upstream = %v; want the primary 10.0.0.1:853", rec["upstream"])
	}
	if rec["timed_out"] != true {
		t.Errorf("timed_out = %v; want true for a hung primary", rec["timed_out"])
	}
	if rem, _ := rec["remediation"].(string); rem == "" {
		t.Errorf("remediation missing or empty: %v", rec)
	}
}

// A fast primary failure is not a timeout. The primary reads no ctx, so a
// stall before it runs cannot turn its failure into a deadline error.
// Serial: runLoggedQuery swaps slog.Default through obs.Capture to assert on log records.
func TestServer_PrimaryFailsFast_WarnNotTimedOut(t *testing.T) {
	primary := &failingResolver{addr: "10.0.0.1:853", err: errors.New("connection refused")}
	fallback := &fakeResolver{addr: "10.0.0.2:853", rcode: dns.RcodeSuccess}
	_, records := runLoggedQuery(t, []dataplane.Resolver{primary, fallback}, "fastfail.example.com.")
	rec := findRecord(records, "WARN", "upstream attempt failed")
	if rec == nil {
		t.Fatalf("no WARN record; records: %v", records)
	}
	if rec["timed_out"] != false {
		t.Errorf("timed_out = %v; want false for a fast failure", rec["timed_out"])
	}
}

// Both fail: `upstream` names the upstream whose error is in `error` (the
// last tried); the primary is in first_upstream / first_error.
// Serial: runLoggedQuery swaps slog.Default through obs.Capture to assert on log records.
func TestServer_BothFail_LogNamesLastTriedUpstream(t *testing.T) {
	primary := hangingResolver(t, "10.0.0.1:853")
	fallback := &fakeResolver{addr: "10.0.0.2:853", err: errors.New("fake upstream 10.0.0.2:853: connection refused")}
	resp, records := runLoggedQuery(t, []dataplane.Resolver{primary, fallback}, "bothfail.example.com.")
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s; want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	rec := findRecord(records, "ERROR", "all upstream resolvers failed")
	if rec == nil {
		t.Fatalf("no ERROR record; records: %v", records)
	}
	if rec["upstream"] != "10.0.0.2:853" {
		t.Errorf("upstream = %v; want the last tried 10.0.0.2:853", rec["upstream"])
	}
	if e, _ := rec["error"].(string); !strings.Contains(e, "10.0.0.2:853") {
		t.Errorf("error = %q; want the last tried upstream's error", e)
	}
	if rec["first_upstream"] != "10.0.0.1:853" {
		t.Errorf("first_upstream = %v; want 10.0.0.1:853", rec["first_upstream"])
	}
	if e, _ := rec["first_error"].(string); !strings.Contains(e, "10.0.0.1:853") {
		t.Errorf("first_error = %q; want the primary's error", e)
	}
}
