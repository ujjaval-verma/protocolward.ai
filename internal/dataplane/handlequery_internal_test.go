// SPDX-License-Identifier: Apache-2.0

// Package dataplane internal tests for handleQuery guard paths.
//
// These tests live in package dataplane (not dataplane_test) so they can call
// the unexported handleQuery method directly. This is necessary for the
// zero-question guard test because miekg/dns DefaultMsgAcceptFunc intercepts
// qdcount=0 messages before the handler is ever invoked — we must invoke the
// handler directly to exercise our defense-in-depth guard.
package dataplane

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/config"
	"protocolward.ai/ward/internal/obs"
	"protocolward.ai/ward/internal/policy"
)

// stubResponseWriter is a minimal dns.ResponseWriter for direct unit-testing
// of handleQuery without a live listener.
type stubResponseWriter struct {
	remoteAddr net.Addr
	written    *dns.Msg
}

func (s *stubResponseWriter) LocalAddr() net.Addr         { return s.remoteAddr }
func (s *stubResponseWriter) RemoteAddr() net.Addr        { return s.remoteAddr }
func (s *stubResponseWriter) WriteMsg(m *dns.Msg) error   { s.written = m; return nil }
func (s *stubResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (s *stubResponseWriter) Close() error                { return nil }
func (s *stubResponseWriter) TsigStatus() error           { return nil }
func (s *stubResponseWriter) TsigTimerOnly(_ bool)        {}
func (s *stubResponseWriter) TsigTimersOnly(_ bool)       {}
func (s *stubResponseWriter) Hijack()                     {}

// stubResolver satisfies Resolver for constructing a Server without a live upstream.
type stubResolver struct{}

func (s *stubResolver) Query(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	return resp, nil
}
func (s *stubResolver) Address() string { return "127.0.0.1:9001" }

// ───────────────────────────────────────────────────────────────────────────
// T7 Ralph B1: Zero-question guard — handleQuery returns FORMERR and logs
// an ERROR with remediation field when req.Question is empty.
// ───────────────────────────────────────────────────────────────────────────

func TestServer_ZeroQuestion_ReturnsFormErr(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	srv, err := NewServer(Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []Resolver{&stubResolver{}},
		QueryTimeout:    2 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = true
	// req.Question is deliberately left empty — this is the zero-question case.

	raddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	w := &stubResponseWriter{remoteAddr: raddr}

	// Call handleQuery directly; no live listener needed.
	srv.handleQuery(w, req)

	if w.written == nil {
		t.Fatal("handleQuery did not write any response")
	}
	if w.written.Rcode != dns.RcodeFormatError {
		t.Errorf("rcode: got %d (%s), want %d (FORMERR)",
			w.written.Rcode, dns.RcodeToString[w.written.Rcode], dns.RcodeFormatError)
	}

	// Verify an ERROR slog line with remediation was emitted (invariant #8).
	// handleQuery is synchronous here so no sleep is needed.
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
		t.Errorf("no ERROR slog line with remediation field found; records: %v", records)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// Invariant #2 runtime backstop: unknown Action value panics with message
// containing "missing handler" and "invariant #2".
// ───────────────────────────────────────────────────────────────────────────

func TestHandleQuery_UnknownAction_Panics(t *testing.T) {
	// Construct a *Server minimally; we exercise the dispatchForTest seam,
	// not the full DNS pipeline.
	s := &Server{
		cfg: Config{
			// BlockResponse with valid mode so writeBlockResponse won't panic
			// for unrelated reasons; we never reach it for Action(255).
			BlockResponse: config.BlockResponseConfig{
				Mode: config.BlockResponseModeAddress,
				A:    netip.MustParseAddr("0.0.0.0"),
				AAAA: netip.MustParseAddr("::"),
			},
		},
	}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for unknown action")
		}
		msg := fmt.Sprintf("%v", r)
		if !strings.Contains(msg, "missing handler") || !strings.Contains(msg, "invariant #2") {
			t.Errorf("panic message %q missing required tokens", msg)
		}
	}()
	bogus := policy.Decision{Action: policy.Action(255)}
	s.dispatchForTest(nil, &dns.Msg{}, bogus)
}

// (c) isConnectivityProbe matches on label boundaries: the zone itself and
// names under it, never look-alikes that merely share a suffix or prefix.
func TestIsConnectivityProbe(t *testing.T) {
	cases := []struct {
		qname string
		want  bool
	}{
		{"msftncsi.com", true},
		{"www.msftncsi.com", true},
		{"a.b.msftncsi.com", true},
		{"notmsftncsi.com", false},
		{"msftncsi.co", false},
		{"msftncsi.com.evil", false},
		{"msftncsi.com.evil.example", false},
		{"", false},
		{"com", false},
	}
	for _, tc := range cases {
		if got := isConnectivityProbe(tc.qname); got != tc.want {
			t.Errorf("isConnectivityProbe(%q) = %v, want %v", tc.qname, got, tc.want)
		}
	}
}
