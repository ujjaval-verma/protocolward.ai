// SPDX-License-Identifier: Apache-2.0

package upstream_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/upstream"
)

// fakeConfig returns a client Config pointing at srv.
func fakeConfig(srv *FakeDoTServer) upstream.Config {
	return upstream.Config{
		Address:     srv.Addr,
		ServerName:  "fake-dot.test",
		TLSConfig:   srv.TLSConf,
		DialTimeout: 2 * time.Second,
	}
}

// newMsg returns an A query for example.com.
func newMsg() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	return m
}

// TestQuery_Burst100At20ms is the issue's acceptance burst: a cold client with
// the default pool answers 100 concurrent queries against a 20 ms upstream in
// under 500 ms. The threshold is fixed and the pool is never pre-warmed.
func TestQuery_Burst100At20ms(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess, Latency: 20 * time.Millisecond})
	client, err := upstream.New(fakeConfig(srv))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer client.Close()

	const n = 100
	start := make(chan struct{})
	errs := make([]error, n)
	rcodes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			resp, err := client.Query(ctx, newMsg())
			if err != nil {
				errs[i] = err
				return
			}
			rcodes[i] = resp.Rcode
		}(i)
	}
	t0 := time.Now()
	close(start)
	wg.Wait()
	elapsed := time.Since(t0)
	t.Logf("burst of %d queries at 20 ms latency took %v", n, elapsed)

	failed := 0
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			if failed == 0 {
				t.Errorf("query %d: %v", i, errs[i])
			}
			failed++
			continue
		}
		if rcodes[i] != dns.RcodeSuccess {
			t.Errorf("query %d: rcode %d, want NOERROR", i, rcodes[i])
		}
	}
	if failed > 0 {
		t.Errorf("%d of %d queries failed", failed, n)
	}
	if elapsed >= 500*time.Millisecond {
		t.Errorf("burst took %v, want < 500ms", elapsed)
	}
	if got := srv.MaxOpen(); got > upstream.DefaultMaxConns {
		t.Errorf("server saw %d connections open at once, want <= %d", got, upstream.DefaultMaxConns)
	}
}

// newPoolClient returns a client for srv with a test-sized pool.
func newPoolClient(t *testing.T, srv *FakeDoTServer, maxConns int, idle time.Duration) *upstream.Client {
	t.Helper()
	client, err := upstream.NewWithPool(fakeConfig(srv), maxConns, idle)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return client
}

// queryResult is the outcome of one asynchronous Query.
type queryResult struct {
	resp    *dns.Msg
	err     error
	elapsed time.Duration
}

// goQuery runs one Query in a goroutine and delivers its result.
func goQuery(client *upstream.Client, ctx context.Context) <-chan queryResult {
	ch := make(chan queryResult, 1)
	go func() {
		t0 := time.Now()
		resp, err := client.Query(ctx, newMsg())
		ch <- queryResult{resp: resp, err: err, elapsed: time.Since(t0)}
	}()
	return ch
}

// awaitQuery waits for a goQuery result, failing the test (instead of hanging
// it) if the query has not returned within bound.
func awaitQuery(t *testing.T, ch <-chan queryResult, bound time.Duration) queryResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(bound):
		t.Fatalf("query did not return within %v", bound)
		return queryResult{}
	}
}

// waitFor polls cond every 5 ms until it holds or bound elapses.
func waitFor(t *testing.T, bound time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", bound, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// startOccupant starts a query that holds the only slot of a pool-1 client
// against a HangUntil server, and waits until the server has read it. The
// occupant's ctx is bounded (1 s), so a client that cannot honour a waiter's
// ctx makes the waiter late rather than hanging the test. The returned stop
// cancels the occupant and waits for it.
func startOccupant(t *testing.T, client *upstream.Client, srv *FakeDoTServer) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	ch := goQuery(client, ctx)
	waitFor(t, time.Second, "the occupant query to reach the server", func() bool { return len(srv.Queries()) == 1 })
	return func() {
		cancel()
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Errorf("occupant did not return within 2s of its cancel")
		}
	}
}

// newHangServer returns a HangUntil server whose hang is released at cleanup.
func newHangServer(t *testing.T) *FakeDoTServer {
	t.Helper()
	hang := make(chan struct{})
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess, HangUntil: hang})
	t.Cleanup(func() { close(hang) })
	return srv
}

func TestQuery_PoolWait_DeadlineExceeded(t *testing.T) {
	srv := newHangServer(t)
	client := newPoolClient(t, srv, 1, time.Minute)
	defer client.Close()
	stop := startOccupant(t, client, srv)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r := awaitQuery(t, goQuery(client, ctx), 2*time.Second)

	if !errors.Is(r.err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", r.err)
	}
	if r.elapsed >= 150*time.Millisecond {
		t.Errorf("waiter returned after %v, want < 150ms", r.elapsed)
	}
	if !strings.Contains(r.err.Error(), "remediation:") {
		t.Errorf("wait error has no remediation: %v", r.err)
	}
	if got := len(srv.Queries()); got != 1 {
		t.Errorf("server read %d queries, want 1 (the waiter must never be sent)", got)
	}
}

func TestQuery_PoolWait_Canceled(t *testing.T) {
	srv := newHangServer(t)
	client := newPoolClient(t, srv, 1, time.Minute)
	defer client.Close()
	stop := startOccupant(t, client, srv)
	defer stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := goQuery(client, ctx)
	time.AfterFunc(50*time.Millisecond, cancel)
	r := awaitQuery(t, ch, 2*time.Second)

	if !errors.Is(r.err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", r.err)
	}
	if r.elapsed >= 150*time.Millisecond {
		t.Errorf("waiter returned after %v, want < 150ms", r.elapsed)
	}
	if !strings.Contains(r.err.Error(), "remediation:") {
		t.Errorf("wait error has no remediation: %v", r.err)
	}
	if got := len(srv.Queries()); got != 1 {
		t.Errorf("server read %d queries, want 1 (the waiter must never be sent)", got)
	}
}

// An already-ended ctx on an idle cold client returns the plain context error
// without taking a slot or dialling.
func TestQuery_PoolWait_AlreadyDone(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess})
	client := newPoolClient(t, srv, 1, time.Minute)
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := awaitQuery(t, goQuery(client, ctx), 2*time.Second)

	if !errors.Is(r.err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", r.err)
	}
	var dialErr *upstream.DialError
	if errors.As(r.err, &dialErr) || strings.Contains(r.err.Error(), "dial failed") {
		t.Errorf("err = %v, want the plain context error, not a dial failure", r.err)
	}
	if got := srv.Conns(); got != 0 {
		t.Errorf("server accepted %d connections, want 0", got)
	}
}

// Simulates the dataplane's two-resolver split: a saturated primary gives up
// at its half of the budget, and the fallback answers inside the rest.
func TestQuery_PoolWait_LeavesBudgetForFallback(t *testing.T) {
	srvPrimary := newHangServer(t)
	primary := newPoolClient(t, srvPrimary, 1, time.Minute)
	defer primary.Close()
	stop := startOccupant(t, primary, srvPrimary)
	defer stop()

	srvFallback := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess, Latency: 20 * time.Millisecond})
	fallback, err := upstream.New(fakeConfig(srvFallback))
	if err != nil {
		t.Fatalf("new fallback: %v", err)
	}
	defer fallback.Close()

	t0 := time.Now()
	parent, cancelParent := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancelParent()
	firstCtx, cancelFirst := context.WithTimeout(parent, 300*time.Millisecond)
	defer cancelFirst()

	rPrimary := awaitQuery(t, goQuery(primary, firstCtx), 2*time.Second)
	if !errors.Is(rPrimary.err, context.DeadlineExceeded) {
		t.Fatalf("primary err = %v, want context.DeadlineExceeded", rPrimary.err)
	}
	if rPrimary.elapsed > 400*time.Millisecond {
		t.Errorf("primary gave up after %v, want <= 400ms (300 ms share + 100 ms)", rPrimary.elapsed)
	}

	rFallback := awaitQuery(t, goQuery(fallback, parent), 2*time.Second)
	if rFallback.err != nil {
		t.Fatalf("fallback err = %v, want an answer within the parent budget", rFallback.err)
	}
	if total := time.Since(t0); total >= 600*time.Millisecond {
		t.Errorf("primary + fallback took %v, want < 600ms", total)
	}
}

// burst fires n concurrent queries, each with its own timeout, and returns
// the errors.
func burst(client *upstream.Client, n int, timeout time.Duration) []error {
	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			_, errs[i] = client.Query(ctx, newMsg())
		}(i)
	}
	close(start)
	wg.Wait()
	return errs
}

func firstErr(errs []error) error {
	for i, err := range errs {
		if err != nil {
			return fmt.Errorf("query %d: %w", i, err)
		}
	}
	return nil
}

func TestQuery_PoolBound(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess, Latency: 20 * time.Millisecond})
	client := newPoolClient(t, srv, 4, time.Minute)
	defer client.Close()

	if err := firstErr(burst(client, 100, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := srv.MaxOpen(); got != 4 {
		t.Errorf("server saw %d connections open at once, want 4 (grow to the bound, never past it)", got)
	}
	if got := srv.Conns(); got != 4 {
		t.Errorf("server accepted %d connections, want 4", got)
	}
}

// The server closes every idle connection (FIN, or RST); the first query hits
// the top stale connection, closes only that one and retries on one fresh
// dial, which then serves the rest from the top of the LIFO stack.
func TestQuery_HalfClosedIdle(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reset bool
	}{
		{"fin", false},
		{"rst", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeDoT(t, FakeDoTOptions{
				Rcode:        dns.RcodeSuccess,
				Latency:      20 * time.Millisecond,
				IdleClose:    50 * time.Millisecond,
				ResetOnClose: tc.reset,
			})
			client, err := upstream.New(fakeConfig(srv))
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			defer client.Close()

			if err := firstErr(burst(client, 4, 2*time.Second)); err != nil {
				t.Fatal(err)
			}
			if got := srv.Conns(); got != 4 {
				t.Fatalf("scheduling precondition, not a pool result: 4 concurrent queries opened %d connections, want 4", got)
			}

			time.Sleep(150 * time.Millisecond) // the server closes all 4

			for i := 0; i < 4; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				t0 := time.Now()
				_, err := client.Query(ctx, newMsg())
				el := time.Since(t0)
				cancel()
				if err != nil {
					t.Fatalf("query %d after the server closed its idle connections: %v", i, err)
				}
				if el >= 500*time.Millisecond {
					t.Errorf("query %d took %v, want < 500ms", i, el)
				}
			}
			if got := srv.Conns(); got != 5 {
				t.Errorf("server accepted %d connections, want 5 (one fresh dial serves all 4)", got)
			}
		})
	}
}

// A deadline from an earlier exchange must not apply to a later one on the
// same connection.
func TestQuery_ReusedConn_ClearsOldDeadline(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess})
	client, err := upstream.New(fakeConfig(srv))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := client.Query(ctx, newMsg()); err != nil {
		t.Fatalf("query 1: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	if _, err := client.Query(context.Background(), newMsg()); err != nil {
		t.Fatalf("query 2: %v", err)
	}
	if got := srv.Conns(); got != 1 {
		t.Errorf("server accepted %d connections, want 1 (query 2 reuses the idle connection)", got)
	}
}

// A query whose ctx ends just after it wins a slot is neither sent nor dialled.
func TestQuery_SlotTaken_CtxEnded_NotSent(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess})
	client := newPoolClient(t, srv, 1, time.Minute)
	defer client.Close()

	var armed atomic.Bool
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	upstream.SetAfterSlotHook(client, func() {
		if armed.Load() {
			cancel2()
		}
	})

	if _, err := client.Query(context.Background(), newMsg()); err != nil {
		t.Fatalf("warm query: %v", err)
	}
	if got := len(srv.Queries()); got != 1 {
		t.Fatalf("server read %d queries after the warm query, want 1", got)
	}
	armed.Store(true)

	r := awaitQuery(t, goQuery(client, ctx2), 2*time.Second)
	if !errors.Is(r.err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", r.err)
	}
	var dialErr *upstream.DialError
	if errors.As(r.err, &dialErr) {
		t.Errorf("err = %v, want the plain context error, not a *DialError", r.err)
	}
	if got := len(srv.Queries()); got != 1 {
		t.Errorf("server read %d queries, want 1 (nothing sent after the slot)", got)
	}
	if got := srv.Conns(); got != 1 {
		t.Errorf("server accepted %d connections, want 1 (nothing dialled after the slot)", got)
	}
}

// A read that hits the query's deadline on a reused connection closes only
// that connection and is neither retried nor redialled.
func TestQuery_ReusedConnDeadline_NoRetry(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess, Latency: 200 * time.Millisecond, IdleClose: time.Minute})
	client := newPoolClient(t, srv, 4, time.Minute)
	defer client.Close()

	if err := firstErr(burst(client, 2, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := srv.Conns(); got != 2 {
		t.Fatalf("scheduling precondition, not a pool result: 2 concurrent queries opened %d connections, want 2", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r := awaitQuery(t, goQuery(client, ctx), 2*time.Second)
	if !errors.Is(r.err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", r.err)
	}
	if r.elapsed >= 150*time.Millisecond {
		t.Errorf("timed-out query returned after %v, want < 150ms", r.elapsed)
	}
	if got := srv.Conns(); got != 2 {
		t.Errorf("server accepted %d connections, want 2 (no redial)", got)
	}
	if got := len(srv.Queries()); got != 3 {
		t.Errorf("server read %d queries, want 3 (no retry)", got)
	}
	waitFor(t, time.Second, "only the timed-out connection to close (Open == 1)", func() bool { return srv.Open() == 1 })

	if _, err := client.Query(context.Background(), newMsg()); err != nil {
		t.Fatalf("final query: %v", err)
	}
	if got := srv.Conns(); got != 2 {
		t.Errorf("server accepted %d connections, want 2 (the other idle connection survived)", got)
	}
}

// main's retry rule is kept: a failure on a freshly dialled connection is
// retried once, on another fresh dial, never more.
func TestQuery_FreshConnFailure_RetriedOnce(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess, CloseWithoutReply: true})
	client, err := upstream.New(fakeConfig(srv))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r := awaitQuery(t, goQuery(client, ctx), 3*time.Second)
	if r.err == nil {
		t.Fatal("expected an error from a server that never replies")
	}
	if errors.Is(r.err, context.DeadlineExceeded) || errors.Is(r.err, context.Canceled) {
		t.Errorf("err = %v, want a transport error, not a ctx error", r.err)
	}
	if !strings.Contains(r.err.Error(), "remediation:") {
		t.Errorf("err has no remediation: %v", r.err)
	}
	if r.elapsed >= time.Second {
		t.Errorf("query returned after %v, want well before its 2s deadline", r.elapsed)
	}
	if got := len(srv.Queries()); got != 2 {
		t.Errorf("server read %d queries, want 2 (one retry)", got)
	}
	if got := srv.Conns(); got != 2 {
		t.Errorf("server accepted %d connections, want 2 (the retry dials fresh)", got)
	}
}

func TestQuery_HandshakeFailure_RetriedOnce(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{CloseOnHandshake: true})
	client, err := upstream.New(fakeConfig(srv))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.Query(ctx, newMsg()); err == nil {
		t.Fatal("expected an error when the server closes on handshake")
	}
	if got := srv.Conns(); got != 2 {
		t.Errorf("server accepted %d connections, want 2 (one retry)", got)
	}
}

// The only idle connection never expires, however long it has been idle.
func TestQuery_IdleExpiry_KeepsMostRecent(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess, IdleClose: time.Minute})
	client := newPoolClient(t, srv, 16, 50*time.Millisecond)
	defer client.Close()

	if _, err := client.Query(context.Background(), newMsg()); err != nil {
		t.Fatalf("query 1: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := client.Query(context.Background(), newMsg()); err != nil {
		t.Fatalf("query 2: %v", err)
	}
	if got := srv.Conns(); got != 1 {
		t.Errorf("server accepted %d connections, want 1 (the most recent idle connection is kept)", got)
	}
}

// Idle connections beyond the most recent one are closed once they expire.
func TestQuery_IdleExpiry_ExtrasClosed(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess, Latency: 20 * time.Millisecond, IdleClose: time.Minute})
	client := newPoolClient(t, srv, 4, 50*time.Millisecond)
	defer client.Close()

	if err := firstErr(burst(client, 4, 2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := srv.Conns(); got != 4 {
		t.Fatalf("scheduling precondition, not a pool result: 4 concurrent queries opened %d connections, want 4", got)
	}
	time.Sleep(100 * time.Millisecond)

	if _, err := client.Query(context.Background(), newMsg()); err != nil {
		t.Fatalf("query after idle: %v", err)
	}
	if got := srv.Conns(); got != 4 {
		t.Errorf("server accepted %d connections, want 4 (the query reuses the top connection)", got)
	}
	waitFor(t, time.Second, "the client to close the 3 expired extras (Open == 1)", func() bool { return srv.Open() == 1 })
}

// wantClosed fails unless err wraps upstream.ErrClosed and names the upstream.
func wantClosed(t *testing.T, what string, err error, addr string) {
	t.Helper()
	if !errors.Is(err, upstream.ErrClosed) {
		t.Errorf("%s: err = %v, want upstream.ErrClosed", what, err)
		return
	}
	if !strings.Contains(err.Error(), addr) {
		t.Errorf("%s: ErrClosed text %q does not name the upstream %s", what, err, addr)
	}
}

func TestClose_UnblocksInFlight(t *testing.T) {
	srv := newHangServer(t)
	client, err := upstream.New(fakeConfig(srv))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch := goQuery(client, ctx)
	waitFor(t, time.Second, "the query to reach the server", func() bool { return len(srv.Queries()) == 1 })

	t0 := time.Now()
	client.Close()
	r := awaitQuery(t, ch, 2*time.Second)
	wantClosed(t, "in-flight query", r.err, srv.Addr)
	if el := time.Since(t0); el >= 200*time.Millisecond {
		t.Errorf("in-flight query returned %v after Close, want < 200ms", el)
	}
}

func TestClose_ReleasesWaiters(t *testing.T) {
	srv := newHangServer(t)
	client := newPoolClient(t, srv, 1, time.Minute)
	defer client.Close()
	stop := startOccupant(t, client, srv)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch := goQuery(client, ctx)
	time.Sleep(50 * time.Millisecond) // let the waiter block on the slot

	t0 := time.Now()
	client.Close()
	r := awaitQuery(t, ch, 2*time.Second)
	wantClosed(t, "waiting query", r.err, srv.Addr)
	if el := time.Since(t0); el >= 200*time.Millisecond {
		t.Errorf("waiting query returned %v after Close, want < 200ms", el)
	}
	if got := srv.Conns(); got != 1 {
		t.Errorf("server accepted %d connections, want 1 (the waiter dials nothing)", got)
	}
}

func TestClose_QueryAfterCloseNoDial(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess})
	client, err := upstream.New(fakeConfig(srv))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := client.Query(context.Background(), newMsg()); err != nil {
		t.Fatalf("warm query: %v", err)
	}
	client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r := awaitQuery(t, goQuery(client, ctx), 3*time.Second)
	wantClosed(t, "query after Close", r.err, srv.Addr)
	if got := srv.Conns(); got != 1 {
		t.Errorf("server accepted %d connections, want 1 (no dial after Close)", got)
	}
}

func TestClose_Idempotent(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess})
	client, err := upstream.New(fakeConfig(srv))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := client.Query(context.Background(), newMsg()); err != nil {
		t.Fatalf("query: %v", err)
	}
	client.Close()
	client.Close()
}

func TestClose_ConcurrentWithQueries(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess, Latency: time.Millisecond})
	client, err := upstream.New(fakeConfig(srv))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer client.Close()

	// A broken build must fail here, not hang: every query runs under a 2 s
	// test deadline, and a goroutine that reaches it without seeing
	// ErrClosed counts as a failure.
	testCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	const n = 50
	sawClosed := make([]bool, n)
	badErr := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for testCtx.Err() == nil {
				_, err := client.Query(testCtx, newMsg())
				switch {
				case err == nil:
				case errors.Is(err, upstream.ErrClosed):
					if !strings.Contains(err.Error(), srv.Addr) {
						badErr[i] = fmt.Errorf("ErrClosed text does not name the upstream: %w", err)
					}
					sawClosed[i] = true
					return
				case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
				case strings.Contains(err.Error(), "remediation:"):
					// a transport error
				default:
					badErr[i] = err
					return
				}
			}
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	client.Close()
	wg.Wait()

	for i := 0; i < n; i++ {
		if badErr[i] != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, badErr[i])
		}
		if !sawClosed[i] {
			t.Errorf("goroutine %d never saw ErrClosed before the 2s test deadline", i)
		}
	}
	waitFor(t, time.Second, "every server connection to close (Open == 0)", func() bool { return srv.Open() == 0 })
}

// A query that wins a slot as Close runs neither reuses nor dials.
func TestClose_AfterSlot_NoDial(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess})
	client := newPoolClient(t, srv, 1, time.Minute)
	upstream.SetAfterSlotHook(client, client.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r := awaitQuery(t, goQuery(client, ctx), 3*time.Second)
	wantClosed(t, "query whose slot raced Close", r.err, srv.Addr)
	if got := srv.Conns(); got != 0 {
		t.Errorf("server accepted %d connections, want 0 (no dial after Close)", got)
	}
}

// Waiters entering checkout concurrently with Close all see ErrClosed, and
// only the occupant's connection is ever dialled.
func TestClose_RacesWaiters_NoDialAfterClose(t *testing.T) {
	for round := 0; round < 5; round++ {
		t.Run(fmt.Sprintf("round%d", round), func(t *testing.T) {
			srv := newHangServer(t)
			client := newPoolClient(t, srv, 1, time.Minute)
			defer client.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			results := make(chan queryResult, 17)
			go func() {
				_, err := client.Query(ctx, newMsg())
				results <- queryResult{err: err}
			}()
			waitFor(t, time.Second, "the occupant to reach the server", func() bool { return len(srv.Queries()) == 1 })

			start := make(chan struct{})
			for i := 0; i < 16; i++ {
				go func() {
					<-start
					_, err := client.Query(ctx, newMsg())
					results <- queryResult{err: err}
				}()
			}
			close(start)
			client.Close()

			timeout := time.After(time.Second)
			for i := 0; i < 17; i++ {
				select {
				case r := <-results:
					wantClosed(t, fmt.Sprintf("query %d", i), r.err, srv.Addr)
				case <-timeout:
					t.Fatalf("only %d of 17 queries returned within 1s of Close", i)
				}
			}
			if got := srv.Conns(); got != 1 {
				t.Errorf("server accepted %d connections, want 1 (only the occupant's)", got)
			}
		})
	}
}
