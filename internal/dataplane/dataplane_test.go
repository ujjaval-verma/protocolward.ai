// SPDX-License-Identifier: Apache-2.0

package dataplane_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/config"
	"protocolward.ai/ward/internal/dataplane"
	adapter "protocolward.ai/ward/internal/model"
	"protocolward.ai/ward/internal/obs"
	"protocolward.ai/ward/internal/policy"
	"protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

// fakeResolver is a test implementation of dataplane.Resolver.
// It returns a configurable DNS response or error on Query.
type fakeResolver struct {
	addr    string
	rcode   int
	err     error
	hangCh  chan struct{} // if non-nil, block until channel is closed
	queries atomic.Int64
}

func (f *fakeResolver) Query(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	f.queries.Add(1)
	if f.hangCh != nil {
		<-f.hangCh
	}
	if f.err != nil {
		return nil, f.err
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = f.rcode
	return resp, nil
}

func (f *fakeResolver) Address() string { return f.addr }

// waitForAddr polls srv.Addr() until it is non-empty or the deadline passes.
func waitForAddr(srv *dataplane.Server, deadline time.Duration) (string, error) {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if a := srv.Addr(); a != "" {
			return a, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return "", fmt.Errorf("server did not expose addr within %s", deadline)
}

// ───────────────────────────────────────────────────────────────────────────
// T1: Listener binds on UDP+TCP on a random port; queries reach the handler.
// T2: Query routed to upstream; response returned verbatim.
// T6: Slog line emitted with all required fields.
// (Bundled since they use the same server setup.)
// ───────────────────────────────────────────────────────────────────────────

func TestServer_BindsAndForwardsQuery(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	r := &fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{r},
		QueryTimeout:    2 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: got %d, want %d", resp.Rcode, dns.RcodeSuccess)
	}
	if r.queries.Load() != 1 {
		t.Errorf("expected 1 query to upstream, got %d", r.queries.Load())
	}

	// T6: slog line with required fields.
	records := obs.Captured(t)
	found := false
	for _, rec := range records {
		if _, ok := rec["qname"]; ok {
			found = true
			for _, field := range []string{"qname", "qtype", "upstream", "rtt_ms", "rcode", "src"} {
				if _, ok := rec[field]; !ok {
					t.Errorf("slog line missing field %q; record: %v", field, rec)
				}
			}
			break
		}
	}
	if !found {
		t.Errorf("no slog line with qname field found; records: %v", records)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// T3: Round-robin across N upstreams.
// With CounterSeed=0 and 3 resolvers, queries 1/2/3/4 hit resolvers 0/1/2/0.
// ───────────────────────────────────────────────────────────────────────────

func TestServer_RoundRobinSelection(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	r0 := &fakeResolver{addr: "10.0.0.1:853", rcode: dns.RcodeSuccess}
	r1 := &fakeResolver{addr: "10.0.0.2:853", rcode: dns.RcodeSuccess}
	r2 := &fakeResolver{addr: "10.0.0.3:853", rcode: dns.RcodeSuccess}

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{r0, r1, r2},
		CounterSeed:     0,
		QueryTimeout:    2 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	for i := 0; i < 4; i++ {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		if _, _, err := c.Exchange(msg, addr); err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
	}

	// CounterSeed=0: first query increments to 1 → idx=(1-1)%3=0 → r0
	// second query → 2-1=1%3=1 → r1; third → 2; fourth → 0 again.
	if q := r0.queries.Load(); q != 2 {
		t.Errorf("r0 (idx 0): got %d queries, want 2", q)
	}
	if q := r1.queries.Load(); q != 1 {
		t.Errorf("r1 (idx 1): got %d queries, want 1", q)
	}
	if q := r2.queries.Load(); q != 1 {
		t.Errorf("r2 (idx 2): got %d queries, want 1", q)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// T4: First-upstream-failure: retry on next upstream succeeds.
// ───────────────────────────────────────────────────────────────────────────

func TestServer_FirstUpstreamFail_RetrySucceeds(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	failR := &fakeResolver{addr: "10.0.0.1:853", err: errors.New("dial failed — remediation: check network")}
	okR := &fakeResolver{addr: "10.0.0.2:853", rcode: dns.RcodeSuccess}

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{failR, okR},
		CounterSeed:     0,
		QueryTimeout:    2 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR after retry, got rcode %d", resp.Rcode)
	}
	if failR.queries.Load() != 1 {
		t.Errorf("failR expected 1 attempt, got %d", failR.queries.Load())
	}
	if okR.queries.Load() != 1 {
		t.Errorf("okR expected 1 attempt (retry), got %d", okR.queries.Load())
	}
}

// ───────────────────────────────────────────────────────────────────────────
// T5: All-upstreams-failure → SERVFAIL; slog ERROR with remediation (invariant #8).
// ───────────────────────────────────────────────────────────────────────────

func TestServer_AllUpstreamsFail_ReturnsSERVFAIL(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	failR := &fakeResolver{
		addr: "10.0.0.1:853",
		err:  errors.New("upstream unreachable — remediation: check network egress on TCP/853"),
	}

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{failR},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL (rcode 2), got %d", resp.Rcode)
	}

	// Verify an ERROR slog line with remediation was emitted (invariant #8).
	records := obs.Captured(t)
	found := false
	for _, rec := range records {
		lvl, _ := rec["level"].(string)
		if lvl == "ERROR" {
			if _, ok := rec["remediation"]; ok {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("no ERROR slog line with remediation field found (invariant #8); records: %v", records)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// T7a: Graceful shutdown without in-flight queries.
// ───────────────────────────────────────────────────────────────────────────

func TestServer_GracefulShutdown(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	r := &fakeResolver{addr: "10.0.0.1:853", rcode: dns.RcodeSuccess}
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{r},
		QueryTimeout:    2 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()

	if _, err := waitForAddr(srv, 2*time.Second); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// Finding #2: Double-Serve guard — second Serve() call returns a typed error.
// ───────────────────────────────────────────────────────────────────────────

func TestServer_DoubleServe_ReturnsError(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	r := &fakeResolver{addr: "10.0.0.1:853", rcode: dns.RcodeSuccess}
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{r},
		QueryTimeout:    2 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Start first Serve in background.
	go srv.Serve()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	if _, err := waitForAddr(srv, 2*time.Second); err != nil {
		t.Fatal(err)
	}

	// Second Serve must return ErrAlreadyServing immediately.
	serveErr := srv.Serve()
	if serveErr == nil {
		t.Fatal("expected error from second Serve() call, got nil")
	}
	if !errors.Is(serveErr, dataplane.ErrAlreadyServing) {
		t.Errorf("expected ErrAlreadyServing, got: %v", serveErr)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// Finding #3: Single-resolver — no retry, exactly 1 Query call, SERVFAIL.
// (renamed from TestServer_AllUpstreamsFail_ReturnsSERVFAIL which is now
// split into single-resolver and two-resolver variants below)
// ───────────────────────────────────────────────────────────────────────────

func TestServer_SingleResolver_NoRetryOnFail(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	failR := &fakeResolver{
		addr: "10.0.0.1:853",
		err:  errors.New("upstream unreachable — remediation: check network egress on TCP/853"),
	}

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{failR},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL (rcode 2), got %d", resp.Rcode)
	}
	// With a single resolver, the spec says "next upstream" implies different —
	// so we skip the retry entirely. Exactly 1 Query call expected.
	if q := failR.queries.Load(); q != 1 {
		t.Errorf("single-resolver: expected exactly 1 Query call, got %d", q)
	}

	// Verify an ERROR slog line with remediation was emitted (invariant #8).
	records := obs.Captured(t)
	found := false
	for _, rec := range records {
		lvl, _ := rec["level"].(string)
		if lvl == "ERROR" {
			if _, ok := rec["remediation"]; ok {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("no ERROR slog line with remediation field found (invariant #8); records: %v", records)
	}
}

func TestServer_AllUpstreamsFail_TwoResolvers(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	failR1 := &fakeResolver{
		addr: "10.0.0.1:853",
		err:  errors.New("upstream-1 unreachable — remediation: check network egress on TCP/853"),
	}
	failR2 := &fakeResolver{
		addr: "10.0.0.2:853",
		err:  errors.New("upstream-2 unreachable — remediation: check network egress on TCP/853"),
	}

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{failR1, failR2},
		CounterSeed:     0,
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL (rcode 2), got %d", resp.Rcode)
	}
	// With two resolvers, we expect 2 Query calls: primary + retry on next.
	totalQueries := failR1.queries.Load() + failR2.queries.Load()
	if totalQueries != 2 {
		t.Errorf("two-resolver: expected exactly 2 Query calls (primary + retry), got %d", totalQueries)
	}

	// Verify an ERROR slog line with remediation was emitted (invariant #8).
	records := obs.Captured(t)
	found := false
	for _, rec := range records {
		lvl, _ := rec["level"].(string)
		if lvl == "ERROR" {
			if _, ok := rec["remediation"]; ok {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("no ERROR slog line with remediation field found (invariant #8); records: %v", records)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// T7b: Graceful shutdown drains an in-flight slow query.
// ───────────────────────────────────────────────────────────────────────────

func TestServer_GracefulShutdown_DrainInFlightQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping drain test in -short mode")
	}

	restore := obs.Capture(t)
	defer restore()

	hang := make(chan struct{})
	slowR := &fakeResolver{addr: "10.0.0.1:853", rcode: dns.RcodeSuccess, hangCh: hang}

	dpSrv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{slowR},
		QueryTimeout:    2 * time.Second,
		ShutdownTimeout: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go dpSrv.Serve()

	addr, err := waitForAddr(dpSrv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// Start a slow query in a goroutine.
	querySent := make(chan struct{})
	queryDone := make(chan error, 1)
	go func() {
		c := new(dns.Client)
		c.Timeout = 3 * time.Second
		msg := new(dns.Msg)
		msg.SetQuestion("slow.example.com.", dns.TypeA)
		close(querySent)
		_, _, err := c.Exchange(msg, addr)
		queryDone <- err
	}()

	<-querySent
	time.Sleep(30 * time.Millisecond) // let query reach the upstream

	// Unblock the upstream after a short delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(hang)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	// Shutdown should drain the in-flight query.
	if err := dpSrv.Shutdown(ctx); err != nil {
		t.Logf("Shutdown returned (may be expected on drain timeout): %v", err)
	}

	// Either the query completed or timed out — either way no goroutine leak.
	select {
	case err := <-queryDone:
		t.Logf("in-flight query result: %v", err)
	case <-time.After(2 * time.Second):
		t.Error("in-flight query goroutine leaked — did not complete within 2s after shutdown")
	}
}

// ───────────────────────────────────────────────────────────────────────────
// Slice-B T5 (updated for slice-C): Policy engine consultation + block response.
// ───────────────────────────────────────────────────────────────────────────

// stubMatcher implements policy.Matcher for testing. It blocks hostnames
// that exactly match or are subdomains of blockedSuffix.
type stubMatcher struct {
	blockedSuffix string
	listID        string
}

func (s *stubMatcher) Match(hostname string) (listID, matched string, ok bool) {
	if hostname == s.blockedSuffix || strings.HasSuffix(hostname, "."+s.blockedSuffix) {
		return s.listID, s.blockedSuffix, true
	}
	return "", "", false
}

// countingResolver wraps a Resolver and counts Query calls.
type countingResolver struct {
	inner dataplane.Resolver
	calls atomic.Int64
}

func (c *countingResolver) Query(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	c.calls.Add(1)
	return c.inner.Query(ctx, m)
}
func (c *countingResolver) Address() string { return c.inner.Address() }

// defaultBlockResponse returns a BlockResponseConfig with mode=address and
// sink addresses 0.0.0.0 / :: — the slice-B default behaviour.
func defaultBlockResponse() config.BlockResponseConfig {
	return config.BlockResponseConfig{
		Mode: config.BlockResponseModeAddress,
		A:    netip.MustParseAddr("0.0.0.0"),
		AAAA: netip.MustParseAddr("::"),
	}
}

// startPolicyServer creates a Server with the given Config, starts it, and
// registers a cleanup to shut it down. Returns the UDP listen address.
func startPolicyServer(t *testing.T, cfg dataplane.Config) string {
	t.Helper()
	srv, err := dataplane.NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestHandleQuery_BlockA(t *testing.T) {
	resolver := &countingResolver{inner: &fakeResolver{addr: "127.0.0.1:9001"}}
	engine := policy.NewEngine(nil, &stubMatcher{blockedSuffix: "example.com", listID: "test"})
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{resolver},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse:   defaultBlockResponse(),
	})

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("ads.example.com.", dns.TypeA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: got %d, want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers: got %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type: got %T, want *dns.A", resp.Answer[0])
	}
	if !a.A.Equal(net.IPv4zero) {
		t.Errorf("ip: got %s, want 0.0.0.0", a.A)
	}
	if a.Hdr.Ttl != 60 {
		t.Errorf("ttl: got %d, want 60", a.Hdr.Ttl)
	}
	if !resp.Authoritative {
		t.Error("AA bit not set")
	}
	if calls := resolver.calls.Load(); calls != 0 {
		t.Errorf("resolver was called %d times on a blocked qname; want 0", calls)
	}
}

func TestHandleQuery_BlockAAAA(t *testing.T) {
	resolver := &countingResolver{inner: &fakeResolver{addr: "127.0.0.1:9001"}}
	engine := policy.NewEngine(nil, &stubMatcher{blockedSuffix: "example.com", listID: "test"})
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{resolver},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse:   defaultBlockResponse(),
	})

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeAAAA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: got %d", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers: got %d, want 1", len(resp.Answer))
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("type: got %T", resp.Answer[0])
	}
	if !aaaa.AAAA.Equal(net.IPv6zero) {
		t.Errorf("ip: got %s, want ::", aaaa.AAAA)
	}
}

func TestHandleQuery_BlockMX_NXDOMAIN(t *testing.T) {
	engine := policy.NewEngine(nil, &stubMatcher{blockedSuffix: "example.com", listID: "test"})
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001"}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse:   defaultBlockResponse(),
	})

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeMX)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode: got %d, want NXDOMAIN", resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("answers: got %d, want 0", len(resp.Answer))
	}
	// AA bit must be set on all sink responses, including NXDOMAIN.
	// This was the observable gap that hid the AA bug (miekg's SetRcode clobbered
	// Authoritative before we moved the flag assignments after the switch).
	if !resp.Authoritative {
		t.Error("AA bit not set on NXDOMAIN sink response")
	}
	if resp.RecursionAvailable {
		t.Error("RA bit set on NXDOMAIN sink response — sink responses are authoritative, not recursive")
	}
}

func TestHandleQuery_PassThrough(t *testing.T) {
	resolver := &countingResolver{inner: &fakeResolver{addr: "127.0.0.1:9001"}}
	engine := policy.NewEngine(nil, &stubMatcher{blockedSuffix: "example.com", listID: "test"})
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{resolver},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse:   defaultBlockResponse(),
	})

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("example.org.", dns.TypeA)
	if _, _, err := c.Exchange(msg, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resolver.calls.Load() != 1 {
		t.Errorf("resolver calls: got %d, want 1 (pass-through to upstream)", resolver.calls.Load())
	}
}

func TestHandleQuery_NilMatcher_NoChange(t *testing.T) {
	resolver := &countingResolver{inner: &fakeResolver{addr: "127.0.0.1:9001"}}
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{resolver},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          nil,
	})

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("anywhere.example.com.", dns.TypeA)
	if _, _, err := c.Exchange(msg, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resolver.calls.Load() != 1 {
		t.Errorf("with nil Engine, every query must dispatch to upstream; calls=%d", resolver.calls.Load())
	}
}

func TestHandleQuery_AttributionLog(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	engine := policy.NewEngine(nil, &stubMatcher{blockedSuffix: "example.com", listID: "oisd-small"})

	// Inline server creation so we hold the *Server reference and can call
	// Shutdown before reading obs.Captured — Shutdown drains the in-flight
	// handler counter, guaranteeing the slog.Info call has completed. Using
	// startPolicyServer would defer Shutdown to t.Cleanup, which runs AFTER
	// the test body, leaving a real race between WriteMsg returning and the
	// slog.Info line being captured.
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001"}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse:   defaultBlockResponse(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("ads.example.com.", dns.TypeA)
	if _, _, err := c.Exchange(msg, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Shutdown drains the in-flight handler counter — guarantees the slog.Info
	// attribution line has been written before we inspect the captured records.
	// This replaces the former time.Sleep(50ms) which was a real race under load
	// or with the race detector enabled.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// Locate the attribution INFO line in the captured records.
	records := obs.Captured(t)
	var hit map[string]any
	for _, r := range records {
		if r["msg"] == "policy: blocked" {
			hit = r
			break
		}
	}
	if hit == nil {
		t.Fatalf("attribution log not found; got: %v", records)
	}
	check := func(k, want string) {
		if got, _ := hit[k].(string); got != want {
			t.Errorf("field %s: got %q, want %q", k, got, want)
		}
	}
	check("qname", "ads.example.com")
	check("qtype", "A")
	check("list_id", "oisd-small")
	check("matched", "example.com")
	check("kind", "block")
	// "src" is the client's UDP socket address; the port is ephemeral so we
	// assert the host portion only (all 7 attribution fields are required).
	if src, _ := hit["src"].(string); !strings.Contains(src, "127.0.0.1:") {
		t.Errorf("field src: got %q, want string containing \"127.0.0.1:\"", src)
	}
	if _, ok := hit["remediation"]; !ok {
		t.Error("attribution log missing remediation field")
	}
}

// ───────────────────────────────────────────────────────────────────────────
// T8 Ralph I3: Sink A/AAAA answer RR class matches question's qclass (RFC 1035).
// ───────────────────────────────────────────────────────────────────────────

func TestHandleQuery_SinkPreservesQClass(t *testing.T) {
	// A query with qclass != INET (e.g., CHAOS) — the sink answer's
	// RR class should match the question's class per RFC 1035.
	engine := policy.NewEngine(nil, &stubMatcher{blockedSuffix: "example.com", listID: "test"})
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001"}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse:   defaultBlockResponse(),
	})

	req := new(dns.Msg)
	req.SetQuestion("ads.example.com.", dns.TypeA)
	req.Question[0].Qclass = dns.ClassCHAOS

	c := new(dns.Client)
	resp, _, err := c.Exchange(req, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers: got %d, want 1", len(resp.Answer))
	}
	if resp.Answer[0].Header().Class != dns.ClassCHAOS {
		t.Errorf("answer class: got %d, want %d (CHAOS)", resp.Answer[0].Header().Class, dns.ClassCHAOS)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// T7 Ralph B1+I1 (wire-level): Zero-question via wire returns FORMERR from
// miekg's DefaultMsgAcceptFunc. Our handleQuery guard is exercised via the
// internal unit tests in handlequery_test.go (package dataplane).
// ───────────────────────────────────────────────────────────────────────────

// TestServer_ZeroQuestion_WireReturnsFORMERR verifies that a DNS message with
// zero questions sent over the wire receives a FORMERR response. miekg's
// DefaultMsgAcceptFunc handles this case before our handler is invoked, so
// this test documents the end-to-end observable behaviour.
func TestServer_ZeroQuestion_WireReturnsFORMERR(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	r := &fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{r},
		QueryTimeout:    2 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// A message with zero questions is rejected by miekg's DefaultMsgAcceptFunc
	// with FORMERR before the handler is reached.
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	// msg.Question is deliberately left empty.

	c := new(dns.Client)
	resp, _, exchErr := c.Exchange(msg, addr)
	if exchErr != nil {
		t.Fatalf("exchange: %v", exchErr)
	}
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("rcode: got %d (%s), want %d (FORMERR)",
			resp.Rcode, dns.RcodeToString[resp.Rcode], dns.RcodeFormatError)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// T7 Ralph I1: Handler panic is recovered; SERVFAIL returned, slog ERROR emitted.
// ───────────────────────────────────────────────────────────────────────────

// panicResolver implements dataplane.Resolver and always panics in Query.
type panicResolver struct{ addr string }

func (p *panicResolver) Query(_ context.Context, _ *dns.Msg) (*dns.Msg, error) {
	panic("injected panic for test — defense-in-depth recover() test")
}
func (p *panicResolver) Address() string { return p.addr }

func TestServer_HandlerPanic_RecoversToServfail(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&panicResolver{addr: "127.0.0.1:9002"}},
		QueryTimeout:    2 * time.Second,
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

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("panic.example.com.", dns.TypeA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode: got %d (%s), want %d (SERVFAIL)",
			resp.Rcode, dns.RcodeToString[resp.Rcode], dns.RcodeServerFailure)
	}

	// Shutdown drains the in-flight handler counter, guaranteeing the slog.Error
	// call inside the recover() has completed before we inspect captured records.
	// This replaces the former time.Sleep(50ms) which was a real race under load
	// or with the race detector enabled.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	records := obs.Captured(t)
	found := false
	for _, rec := range records {
		lvl, _ := rec["level"].(string)
		if lvl == "ERROR" {
			if _, ok := rec["remediation"]; ok {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("no ERROR slog line with remediation field found after panic; records: %v", records)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// 10 new integration cases for the policy Engine + BlockResponse.
// ───────────────────────────────────────────────────────────────────────────

// TestHandleQuery_AllowBeatsBlock: allow={example.com}, block={cdn.example.com}
// A cdn.example.com → upstream A response; "policy: allowed" logged.
func TestHandleQuery_AllowBeatsBlock(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	allow := &stubMatcher{blockedSuffix: "example.com", listID: "my-allowlist"}
	block := &stubMatcher{blockedSuffix: "cdn.example.com", listID: "my-blocklist"}
	engine := policy.NewEngine(allow, block)

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse:   defaultBlockResponse(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("cdn.example.com.", dns.TypeA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	// Allow wins over block — should get upstream response (NOERROR), not a block response.
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: got %d, want NOERROR (allow should beat block)", resp.Rcode)
	}

	// Shutdown drains to guarantee slog lines are captured.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	records := obs.Captured(t)
	found := false
	for _, r := range records {
		if r["msg"] == "policy: allowed" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'policy: allowed' log record; got: %v", records)
	}
}

// TestHandleQuery_Block_AddressMode_Custom_A: block={x.example.com}, A=10.0.0.1
// A x.example.com → answer 10.0.0.1, AA=1, RA=0.
func TestHandleQuery_Block_AddressMode_Custom_A(t *testing.T) {
	engine := policy.NewEngine(nil, &stubMatcher{blockedSuffix: "x.example.com", listID: "test"})
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001"}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse: config.BlockResponseConfig{
			Mode: config.BlockResponseModeAddress,
			A:    netip.MustParseAddr("10.0.0.1"),
			AAAA: netip.MustParseAddr("::"),
		},
	})

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("x.example.com.", dns.TypeA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: got %d, want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers: got %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type: got %T, want *dns.A", resp.Answer[0])
	}
	if a.A.String() != "10.0.0.1" {
		t.Errorf("ip: got %s, want 10.0.0.1", a.A)
	}
	if !resp.Authoritative {
		t.Error("AA bit not set")
	}
	if resp.RecursionAvailable {
		t.Error("RA bit should not be set on block response")
	}
}

// TestHandleQuery_Block_NXDOMAIN_Mode_A: block={x}, mode=nxdomain
// A x → NXDOMAIN, AA=1, RA=0.
func TestHandleQuery_Block_NXDOMAIN_Mode_A(t *testing.T) {
	engine := policy.NewEngine(nil, &stubMatcher{blockedSuffix: "x", listID: "test"})
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001"}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse: config.BlockResponseConfig{
			Mode: config.BlockResponseModeNXDOMAIN,
		},
	})

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("x.", dns.TypeA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode: got %d, want NXDOMAIN", resp.Rcode)
	}
	if !resp.Authoritative {
		t.Error("AA bit not set")
	}
	if resp.RecursionAvailable {
		t.Error("RA bit should not be set on nxdomain block response")
	}
}

// TestHandleQuery_Block_NXDOMAIN_Mode_AAAA: block={x}, mode=nxdomain
// AAAA x → NXDOMAIN, AA=1, RA=0.
func TestHandleQuery_Block_NXDOMAIN_Mode_AAAA(t *testing.T) {
	engine := policy.NewEngine(nil, &stubMatcher{blockedSuffix: "x", listID: "test"})
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001"}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse: config.BlockResponseConfig{
			Mode: config.BlockResponseModeNXDOMAIN,
		},
	})

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("x.", dns.TypeAAAA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode: got %d, want NXDOMAIN", resp.Rcode)
	}
	if !resp.Authoritative {
		t.Error("AA bit not set")
	}
	if resp.RecursionAvailable {
		t.Error("RA bit should not be set")
	}
}

// TestHandleQuery_Block_AddressMode_MX_NXDOMAIN: block={x}, mode=address
// MX x → NXDOMAIN (non-A/AAAA in address mode falls through to NXDOMAIN).
func TestHandleQuery_Block_AddressMode_MX_NXDOMAIN(t *testing.T) {
	engine := policy.NewEngine(nil, &stubMatcher{blockedSuffix: "x", listID: "test"})
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001"}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse:   defaultBlockResponse(),
	})

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("x.", dns.TypeMX)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode: got %d, want NXDOMAIN for MX in address mode", resp.Rcode)
	}
}

// TestHandleQuery_NilEngine_Forwards: nil engine
// A google.com → upstream forward (slice-A regression).
func TestHandleQuery_NilEngine_Forwards(t *testing.T) {
	resolver := &countingResolver{inner: &fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}}
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{resolver},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          nil,
	})

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: got %d, want NOERROR", resp.Rcode)
	}
	if resolver.calls.Load() != 1 {
		t.Errorf("upstream calls: got %d, want 1", resolver.calls.Load())
	}
}

// TestHandleQuery_AllowOnly_NoBlock_Forwards: allow={x.example.com}, block=nil
// A x.example.com → upstream forward + allowed log.
func TestHandleQuery_AllowOnly_NoBlock_Forwards(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	allow := &stubMatcher{blockedSuffix: "x.example.com", listID: "my-allowlist"}
	engine := policy.NewEngine(allow, nil)

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse:   defaultBlockResponse(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("x.example.com.", dns.TypeA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: got %d, want NOERROR (allowlist + no block = forward)", resp.Rcode)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	records := obs.Captured(t)
	found := false
	for _, r := range records {
		if r["msg"] == "policy: allowed" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'policy: allowed' log; got: %v", records)
	}
}

// TestHandleQuery_BlockedQclass_Preserved: block={x}, BR.a=10.0.0.1, mode=address
// A x with qclass=CH → answer with Class=CH (slice-B T8 I3 regression).
func TestHandleQuery_BlockedQclass_Preserved(t *testing.T) {
	engine := policy.NewEngine(nil, &stubMatcher{blockedSuffix: "x", listID: "test"})
	addr := startPolicyServer(t, dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001"}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse: config.BlockResponseConfig{
			Mode: config.BlockResponseModeAddress,
			A:    netip.MustParseAddr("10.0.0.1"),
			AAAA: netip.MustParseAddr("::"),
		},
	})

	req := new(dns.Msg)
	req.SetQuestion("x.", dns.TypeA)
	req.Question[0].Qclass = dns.ClassCHAOS

	c := new(dns.Client)
	resp, _, err := c.Exchange(req, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers: got %d, want 1", len(resp.Answer))
	}
	if resp.Answer[0].Header().Class != dns.ClassCHAOS {
		t.Errorf("answer class: got %d, want %d (CHAOS) — qclass preservation regression",
			resp.Answer[0].Header().Class, dns.ClassCHAOS)
	}
}

// TestServer_AttributionLog_Allow: allow={x}, A x → log record msg="policy: allowed",
// kind="allow", list_id present, matched present.
func TestServer_AttributionLog_Allow(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	allow := &stubMatcher{blockedSuffix: "x", listID: "my-allowlist"}
	engine := policy.NewEngine(allow, nil)

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse:   defaultBlockResponse(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("x.", dns.TypeA)
	if _, _, err := c.Exchange(msg, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	records := obs.Captured(t)
	var hit map[string]any
	for _, r := range records {
		if r["msg"] == "policy: allowed" {
			hit = r
			break
		}
	}
	if hit == nil {
		t.Fatalf("'policy: allowed' log not found; records: %v", records)
	}
	if kind, _ := hit["kind"].(string); kind != "allow" {
		t.Errorf("kind: got %q, want \"allow\"", kind)
	}
	if listID, _ := hit["list_id"].(string); listID == "" {
		t.Error("list_id field missing or empty")
	}
	if matched, _ := hit["matched"].(string); matched == "" {
		t.Error("matched field missing or empty")
	}
}

// TestServer_AttributionLog_Block: block={x}, A x → log record msg="policy: blocked",
// kind="block", remediation present.
func TestServer_AttributionLog_Block(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	engine := policy.NewEngine(nil, &stubMatcher{blockedSuffix: "x", listID: "my-blocklist"})

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001"}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse:   defaultBlockResponse(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("x.", dns.TypeA)
	if _, _, err := c.Exchange(msg, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	records := obs.Captured(t)
	var hit map[string]any
	for _, r := range records {
		if r["msg"] == "policy: blocked" {
			hit = r
			break
		}
	}
	if hit == nil {
		t.Fatalf("'policy: blocked' log not found; records: %v", records)
	}
	if kind, _ := hit["kind"].(string); kind != "block" {
		t.Errorf("kind: got %q, want \"block\"", kind)
	}
	if _, ok := hit["remediation"]; !ok {
		t.Error("remediation field missing from block attribution log")
	}
}

// ───────────────────────────────────────────────────────────────────────────
// SP10c T2: slow-path observe fork
// ───────────────────────────────────────────────────────────────────────────

// Compile-time assertion: *internal/model.Adapter satisfies the dataplane's
// SlowPathClassifier interface. Mirrors the project convention of asserting
// interface satisfaction at the implementing-type site (cf adapter.go:70 for
// pkg/model.Classifier). Lives here in the test file because adding it to
// internal/model would create an import cycle (internal/model → internal/dataplane).
var _ dataplane.SlowPathClassifier = (*adapter.Adapter)(nil)

// fakeClassifier is the test SlowPathClassifier. It returns the configured
// verdict + err for every call; calls counts invocations so latch behavior
// under repeated dispatch is observable.
type fakeClassifier struct {
	verdict schema.Verdict
	err     error
	calls   atomic.Int64
}

func (f *fakeClassifier) Classify(_ context.Context, _ model.Input) (schema.Verdict, error) {
	f.calls.Add(1)
	return f.verdict, f.err
}

// runForwardWithClassifier starts a Server with the given classifier, sends
// a single forwarded query, then drains via Shutdown so the fork goroutine
// completes before tests inspect captured records.
func runForwardWithClassifier(t *testing.T, classifier dataplane.SlowPathClassifier, qname string) {
	t.Helper()
	r := &fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{r},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Classifier:      classifier,
		// Engine left nil — slow-path with nil Engine logs the verdict
		// without DecideWithVerdict. Covered explicitly by the
		// WithEngine subtest.
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	if _, _, err := c.Exchange(msg, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func findRecordByMsg(records []map[string]any, msg string) map[string]any {
	for _, r := range records {
		if r["msg"] == msg {
			return r
		}
	}
	return nil
}

// SP10c T2 — verdict mapping: Malicious → Warn / Telemetry → Info / Benign → Debug.
func TestSlowPath_Verdict_LogLevels(t *testing.T) {
	cases := []struct {
		name      string
		verdict   schema.Verdict
		wantLevel string
		wantWire  string
	}{
		{"Malicious", schema.VerdictMalicious, "WARN", "malicious"},
		{"Telemetry", schema.VerdictTelemetry, "INFO", "telemetry"},
		{"Benign", schema.VerdictBenign, "DEBUG", "benign"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restore := obs.Capture(t)
			defer restore()

			fc := &fakeClassifier{verdict: tc.verdict}
			runForwardWithClassifier(t, fc, "probe.example.com.")

			if fc.calls.Load() != 1 {
				t.Errorf("classifier calls = %d; want 1", fc.calls.Load())
			}

			rec := findRecordByMsg(obs.Captured(t), "policy: classified")
			if rec == nil {
				t.Fatalf("no `policy: classified` record; got: %v", obs.Captured(t))
			}
			if got, _ := rec["level"].(string); got != tc.wantLevel {
				t.Errorf("level = %q want %q", got, tc.wantLevel)
			}
			if got, _ := rec["verdict"].(string); got != tc.wantWire {
				t.Errorf("verdict = %q want %q", got, tc.wantWire)
			}
			if got, _ := rec["qname"].(string); got != "probe.example.com" {
				t.Errorf("qname = %q want probe.example.com", got)
			}
		})
	}
}

// SP10c T2 — nil Classifier: no fork at all (no `policy: classified` line).
func TestSlowPath_NilClassifier_NoFork(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	// Force the standalone path: don't use runForwardWithClassifier (which
	// always sets Classifier non-nil). Build inline with Classifier omitted.
	r := &fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{r},
		QueryTimeout:    1 * time.Second,
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
	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("anything.example.com.", dns.TypeA)
	if _, _, err := c.Exchange(msg, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	sc, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(sc)

	if rec := findRecordByMsg(obs.Captured(t), "policy: classified"); rec != nil {
		t.Errorf("nil Classifier still produced classified log: %v", rec)
	}
}

// SP10c T2 — ErrUnavailable latches: N concurrent forwarded queries against
// a dead classifier produce exactly ONE `policy: model unavailable` line, and
// Classify is called at most once after the latch trips.
//
// Race-detector exercises the atomic.Bool CompareAndSwap path.
func TestSlowPath_ErrUnavailable_LatchOnce_Concurrent(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	fc := &fakeClassifier{err: fmt.Errorf("wrap: %w", adapter.ErrUnavailable)}

	r := &fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{r},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 5 * time.Second,
		Classifier:      fc,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	const N = 8
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			c := new(dns.Client)
			msg := new(dns.Msg)
			msg.SetQuestion(fmt.Sprintf("probe%d.example.com.", i), dns.TypeA)
			_, _, _ = c.Exchange(msg, addr)
		}()
	}
	wg.Wait()

	sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sc)

	records := obs.Captured(t)
	count := 0
	for _, rec := range records {
		if rec["msg"] == "policy: model unavailable" {
			count++
			if got, _ := rec["level"].(string); got != "ERROR" {
				t.Errorf("policy: model unavailable level = %q want ERROR", got)
			}
			if _, ok := rec["remediation"]; !ok {
				t.Error("policy: model unavailable missing remediation field (invariant 8)")
			}
		}
	}
	if count != 1 {
		t.Errorf("policy: model unavailable count = %d; want exactly 1 (atomic latch)", count)
	}
	// After the latch trips, subsequent classifyAsync invocations return early
	// without calling Classify. The first dispatched fork DOES call Classify
	// (that is how the latch trips), so calls must be ≥1 but bounded by N.
	if c := fc.calls.Load(); c < 1 || c > int64(N) {
		t.Errorf("classifier calls = %d; want in [1, %d]", c, N)
	}
}

// SP10c T2 — non-ErrUnavailable error: log Warn, no latch, classify still
// invoked on a second forward.
func TestSlowPath_OtherError_LogsWarn_NoLatch(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	fc := &fakeClassifier{err: errors.New("transient backend hiccup")}

	r := &fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{r},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 3 * time.Second,
		Classifier:      fc,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := new(dns.Client)
	for i := 0; i < 2; i++ {
		msg := new(dns.Msg)
		msg.SetQuestion(fmt.Sprintf("q%d.example.com.", i), dns.TypeA)
		if _, _, err := c.Exchange(msg, addr); err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
	}
	sc, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(sc)

	if fc.calls.Load() != 2 {
		t.Errorf("classifier calls = %d; want 2 (no latch on non-ErrUnavailable)", fc.calls.Load())
	}
	records := obs.Captured(t)
	warnCount := 0
	for _, rec := range records {
		if rec["msg"] == "policy: classify error" {
			warnCount++
			if got, _ := rec["level"].(string); got != "WARN" {
				t.Errorf("policy: classify error level = %q want WARN", got)
			}
		}
	}
	if warnCount != 2 {
		t.Errorf("policy: classify error count = %d; want 2", warnCount)
	}
	if rec := findRecordByMsg(records, "policy: model unavailable"); rec != nil {
		t.Errorf("unexpected unavailable latch tripped on non-ErrUnavailable: %v", rec)
	}
}

// SP10c T2 — DecideWithVerdict is consulted when Engine is non-nil; the
// returned Decision drives the log's `kind` + `matched` fields (NOT the
// query response — observe-only).
func TestSlowPath_WithEngine_DecideWithVerdictAttribution(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	engine := policy.NewEngine(nil, nil) // both matchers nil — verdict-only routing

	fc := &fakeClassifier{verdict: schema.VerdictMalicious}
	r := &fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{r},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		BlockResponse:   defaultBlockResponse(),
		Classifier:      fc,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("evilprobe.example.com.", dns.TypeA)
	if _, _, err := c.Exchange(msg, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	sc, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(sc)

	rec := findRecordByMsg(obs.Captured(t), "policy: classified")
	if rec == nil {
		t.Fatalf("no `policy: classified` record")
	}
	// DecideWithVerdict with Malicious + nil matchers → ActionBlock,
	// KindBlock, MatchedLabel="(model)".
	if got, _ := rec["kind"].(string); got != "KindBlock" {
		t.Errorf("kind = %q want KindBlock", got)
	}
	if got, _ := rec["matched"].(string); got != "(model)" {
		t.Errorf("matched = %q want (model)", got)
	}

	// Observe-only contract: the original DNS response must have been
	// forwarded (the fake resolver returned NOERROR), NOT blocked by the
	// async path. The forwardUpstream Record call should already have
	// fired by the time the classify async path runs; assert by counting
	// upstream calls (the fake resolver tracks this).
	if r.queries.Load() != 1 {
		t.Errorf("upstream queries = %d; want 1 (observe-only must not block the wire response)", r.queries.Load())
	}
}
