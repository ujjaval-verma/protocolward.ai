// SPDX-License-Identifier: Apache-2.0

package dataplane_test

import (
	"context"
	"errors"
	"strings"
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

// A primary that fails fast leaves the fallback the rest of the budget, not
// a fixed half: a fallback that needs 70% of the budget still answers.
func TestServer_PrimaryFailsFast_FallbackGetsRemainingBudget(t *testing.T) {
	t.Parallel()
	primary := &fakeResolver{addr: "10.0.0.1:853", err: errors.New("connection refused")}
	fallback := &fakeResolver{addr: "10.0.0.2:853", rcode: dns.RcodeSuccess, delay: failoverBudget * 7 / 10}
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{primary, fallback},
		QueryTimeout:    failoverBudget,
		ShutdownTimeout: 2 * time.Second,
	})

	resp, _ := exchangeTimed(t, addr, "slowfallback.example.com.")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s; want NOERROR (fallback had 70%% of the budget left)", dns.RcodeToString[resp.Rcode])
	}
}

// With one resolver there is nothing to fail over to, so its single attempt
// keeps the whole budget.
func TestServer_SingleResolver_KeepsWholeBudget(t *testing.T) {
	t.Parallel()
	only := &fakeResolver{addr: "10.0.0.1:853", rcode: dns.RcodeSuccess, delay: failoverBudget * 7 / 10}
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{only},
		QueryTimeout:    failoverBudget,
		ShutdownTimeout: 2 * time.Second,
	})

	resp, _ := exchangeTimed(t, addr, "single.example.com.")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s; want NOERROR (single resolver keeps the whole budget)", dns.RcodeToString[resp.Rcode])
	}
}

// Issue #15: the primary hangs, the fallback is healthy. The fallback must
// answer, inside the configured budget.
func TestServer_PrimaryHangs_FallbackAnswersWithinBudget(t *testing.T) {
	t.Parallel()
	primary := hangingResolver(t, "10.0.0.1:853")
	fallback := &fakeResolver{addr: "10.0.0.2:853", rcode: dns.RcodeSuccess}
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{primary, fallback},
		CounterSeed:     0,
		QueryTimeout:    failoverBudget,
		ShutdownTimeout: 2 * time.Second,
	})

	resp, elapsed := exchangeTimed(t, addr, "hang.example.com.")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s after %s; want NOERROR from the fallback", dns.RcodeToString[resp.Rcode], elapsed)
	}
	if got := primary.queries.Load(); got != 1 {
		t.Errorf("primary attempts = %d; want 1", got)
	}
	if got := fallback.queries.Load(); got != 1 {
		t.Errorf("fallback attempts = %d; want 1", got)
	}
	if elapsed >= failoverBudget+failoverSlack {
		t.Errorf("answered after %s; want under budget %s (+%s slack)", elapsed, failoverBudget, failoverSlack)
	}
}

// The primary hangs and the fallback needs 30% of the budget. The primary
// is capped at half, so the fallback still has 50% left and answers. A
// primary cap above 70% would starve it (guards the query/2 split).
func TestServer_PrimaryHangs_FallbackNeedingThirtyPercentAnswers(t *testing.T) {
	t.Parallel()
	primary := hangingResolver(t, "10.0.0.1:853")
	fallback := &fakeResolver{addr: "10.0.0.2:853", rcode: dns.RcodeSuccess, delay: failoverBudget * 3 / 10}
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{primary, fallback},
		CounterSeed:     0,
		QueryTimeout:    failoverBudget,
		ShutdownTimeout: 2 * time.Second,
	})

	resp, elapsed := exchangeTimed(t, addr, "slowfallback2.example.com.")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s after %s; want NOERROR (fallback had half the budget left)", dns.RcodeToString[resp.Rcode], elapsed)
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
	fallback := &fakeResolver{addr: "10.0.0.2:853", rcode: dns.RcodeSuccess}
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

// A fast primary failure is not a timeout.
// Serial: runLoggedQuery swaps slog.Default through obs.Capture to assert on log records.
func TestServer_PrimaryFailsFast_WarnNotTimedOut(t *testing.T) {
	primary := &fakeResolver{addr: "10.0.0.1:853", err: errors.New("connection refused")}
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
