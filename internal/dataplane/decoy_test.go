// SPDX-License-Identifier: Apache-2.0

package dataplane_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/dataplane"
	"protocolward.ai/ward/internal/decoy"
	"protocolward.ai/ward/internal/hostlist"
	"protocolward.ai/ward/internal/obs"
	"protocolward.ai/ward/internal/policy"
)

func writeDecoyFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "decoys.txt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func newDecoySet(t *testing.T, body string) *decoy.Set {
	t.Helper()
	p := writeDecoyFile(t, body)
	set, _, err := decoy.New([]hostlist.Source{{ID: "test-decoys", Path: p}})
	if err != nil {
		t.Fatalf("decoy.New: %v", err)
	}
	return set
}

// TestHandleQuery_Decoy_Alerts_And_Sinkholes confirms a decoy hit produces
// (a) the configured block response on the wire and (b) a "policy: alert"
// log line at WARN level. The upstream resolver MUST NOT be called.
func TestHandleQuery_Decoy_Alerts_And_Sinkholes(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	decoys := newDecoySet(t, "0.0.0.0 tripwire.dod.test\n")
	resolver := &countingResolver{inner: &fakeResolver{addr: "127.0.0.1:9001"}}

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{resolver},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          nil, // engine is irrelevant for decoy short-circuit
		Decoys:          decoys,
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
	msg.SetQuestion("tripwire.dod.test.", dns.TypeA)
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: got %d, want NOERROR (configured block response is address-mode)", resp.Rcode)
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

	if resolver.calls.Load() != 0 {
		t.Errorf("resolver was called %d times on a decoy hit; want 0 — forwarding would leak the decoy name upstream", resolver.calls.Load())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	records := obs.Captured(t)
	var hit map[string]any
	for _, r := range records {
		if r["msg"] == "policy: alert" {
			hit = r
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected policy: alert log line; got: %v", records)
	}
	if lvl, _ := hit["level"].(string); !strings.EqualFold(lvl, "warn") {
		t.Errorf("level: got %q, want WARN (decoy alert is higher-severity than routine block)", lvl)
	}
	check := func(k, want string) {
		if got, _ := hit[k].(string); got != want {
			t.Errorf("field %s: got %q, want %q", k, got, want)
		}
	}
	check("qname", "tripwire.dod.test")
	check("qtype", "A")
	check("decoy_id", "test-decoys")
	check("kind", "decoy")
	check("matched", "tripwire.dod.test")
	if rem, ok := hit["remediation"].(string); !ok || rem == "" {
		t.Error("policy: alert missing remediation field (invariant 8)")
	}
}

// TestHandleQuery_DecoyBeatsAllowlist: a hostname present BOTH on the
// allowlist AND in the decoy set must trip the alert and NOT be forwarded.
// Decoy short-circuit fires before Engine.Decide so allowlist cannot mask
// the alarm.
func TestHandleQuery_DecoyBeatsAllowlist(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	decoys := newDecoySet(t, "0.0.0.0 vault.internal\n")
	// Build an allowlist matcher whose Match returns true for vault.internal.
	allow := &stubMatcher{blockedSuffix: "vault.internal", listID: "allow-list"}
	engine := policy.NewEngine(allow, nil)
	resolver := &countingResolver{inner: &fakeResolver{addr: "127.0.0.1:9001"}}

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{resolver},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		Decoys:          decoys,
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
	msg.SetQuestion("vault.internal.", dns.TypeA)
	if _, _, err := c.Exchange(msg, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if resolver.calls.Load() != 0 {
		t.Errorf("decoy must short-circuit allowlist; resolver calls=%d want 0", resolver.calls.Load())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	records := obs.Captured(t)
	for _, r := range records {
		if r["msg"] == "policy: allowed" {
			t.Errorf("unexpected policy: allowed log — decoy must short-circuit before Engine.Decide; record: %v", r)
		}
	}
	var alertHit bool
	for _, r := range records {
		if r["msg"] == "policy: alert" {
			alertHit = true
			break
		}
	}
	if !alertHit {
		t.Errorf("expected policy: alert; got: %v", records)
	}
}

// TestHandleQuery_DecoyMiss_FallsThroughToEngine: non-decoy queries must
// still flow through Engine.Decide. Sanity: confirms the short-circuit only
// fires on actual decoy hits.
func TestHandleQuery_DecoyMiss_FallsThroughToEngine(t *testing.T) {
	decoys := newDecoySet(t, "0.0.0.0 only.this.decoy\n")
	resolver := &countingResolver{inner: &fakeResolver{addr: "127.0.0.1:9001"}}

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{resolver},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Decoys:          decoys,
		BlockResponse:   defaultBlockResponse(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	defer srv.Shutdown(context.Background())

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("regular.example.com.", dns.TypeA)
	if _, _, err := c.Exchange(msg, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resolver.calls.Load() != 1 {
		t.Errorf("non-decoy query must forward; resolver calls=%d want 1", resolver.calls.Load())
	}
}

// captureRecorder is a test stub that captures every Record call for assertions.
type captureRecorder struct {
	mu      sync.Mutex
	records []captureRecord
}

type captureRecord struct {
	Qname   string
	Action  string
	Matched string
}

func (c *captureRecorder) Record(qname, action, matched string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, captureRecord{Qname: qname, Action: action, Matched: matched})
}

func (c *captureRecorder) all() []captureRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]captureRecord, len(c.records))
	copy(out, c.records)
	return out
}

// TestHandleQuery_DecisionRecorder_DecoyHit confirms the Record hook fires
// on the decoy short-circuit branch with action="decoy".
func TestHandleQuery_DecisionRecorder_DecoyHit(t *testing.T) {
	decoys := newDecoySet(t, "0.0.0.0 tripwire.dod.test\n")
	rec := &captureRecorder{}

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001"}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Decoys:          decoys,
		Decisions:       rec,
		BlockResponse:   defaultBlockResponse(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	defer srv.Shutdown(context.Background())

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("tripwire.dod.test.", dns.TypeA)
	if _, _, err := c.Exchange(msg, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Drain via Shutdown so we know the handler returned.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)

	records := rec.all()
	if len(records) != 1 {
		t.Fatalf("records: got %d want 1; got=%+v", len(records), records)
	}
	r := records[0]
	if r.Qname != "tripwire.dod.test" || r.Action != "decoy" || r.Matched != "tripwire.dod.test" {
		t.Errorf("record: got %+v", r)
	}
}

// TestHandleQuery_DecisionRecorder_ForwardPath confirms forward decisions
// also fire Record with action="forward".
func TestHandleQuery_DecisionRecorder_ForwardPath(t *testing.T) {
	rec := &captureRecorder{}
	resolver := &countingResolver{inner: &fakeResolver{addr: "127.0.0.1:9001"}}

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{resolver},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Decisions:       rec,
		BlockResponse:   defaultBlockResponse(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	defer srv.Shutdown(context.Background())

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("forwarded.example.com.", dns.TypeA)
	if _, _, err := c.Exchange(msg, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)

	records := rec.all()
	if len(records) != 1 {
		t.Fatalf("records: got %d want 1", len(records))
	}
	if records[0].Qname != "forwarded.example.com" || records[0].Action != "forward" {
		t.Errorf("record: got %+v want qname=forwarded.example.com action=forward", records[0])
	}
}

// TestHandleQuery_DecisionRecorder_BlockHit confirms a block-path query
// produces Record(qname, "block", matchedLabel).
func TestHandleQuery_DecisionRecorder_BlockHit(t *testing.T) {
	rec := &captureRecorder{}
	engine := policy.NewEngine(nil, &stubMatcher{blockedSuffix: "example.com", listID: "blk"})

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001"}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		Decisions:       rec,
		BlockResponse:   defaultBlockResponse(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	defer srv.Shutdown(context.Background())

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

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)

	records := rec.all()
	if len(records) != 1 || records[0].Qname != "ads.example.com" || records[0].Action != "block" || records[0].Matched != "example.com" {
		t.Errorf("records: got %+v want [{ads.example.com block example.com}]", records)
	}
}

// TestHandleQuery_DecisionRecorder_AllowHit confirms an allow-path query
// produces Record(qname, "allow", matchedLabel) AFTER the forward returns.
func TestHandleQuery_DecisionRecorder_AllowHit(t *testing.T) {
	rec := &captureRecorder{}
	allow := &stubMatcher{blockedSuffix: "example.com", listID: "allow-list"}
	engine := policy.NewEngine(allow, nil)

	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001"}},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          engine,
		Decisions:       rec,
		BlockResponse:   defaultBlockResponse(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	defer srv.Shutdown(context.Background())

	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("ok.example.com.", dns.TypeA)
	if _, _, err := c.Exchange(msg, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)

	records := rec.all()
	if len(records) != 1 || records[0].Qname != "ok.example.com" || records[0].Action != "allow" {
		t.Errorf("records: got %+v want one allow record", records)
	}
}
