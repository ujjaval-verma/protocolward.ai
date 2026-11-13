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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/config"
	"protocolward.ai/ward/internal/decoy"
	"protocolward.ai/ward/internal/hostlist"
	"protocolward.ai/ward/internal/obs"
	"protocolward.ai/ward/internal/policy"
	"protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
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

// Serial: swaps slog.Default through obs.Capture to assert on log records.
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
	t.Parallel()
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
	t.Parallel()
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

// failingResponseWriter fails every WriteMsg.
type failingResponseWriter struct{ stubResponseWriter }

func (*failingResponseWriter) WriteMsg(*dns.Msg) error { return errors.New("write failed") }

// TestWriteBlockResponse_WriteFailureLogsFoldedQname pins that the write
// failure line names the query the way the other policy lines do: folded.
// Serial: swaps slog.Default through obs.Capture to assert on log records.
func TestWriteBlockResponse_WriteFailureLogsFoldedQname(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	s := &Server{cfg: Config{BlockResponse: config.BlockResponseConfig{Mode: config.BlockResponseModeNXDOMAIN}}}
	req := new(dns.Msg)
	req.SetQuestion("Ads.Example.COM.", dns.TypeA)
	s.writeBlockResponse(&failingResponseWriter{}, req)

	for _, rec := range obs.Captured(t) {
		if msg, _ := rec["msg"].(string); strings.Contains(msg, "failed to write block response") {
			if got := rec["qname"]; got != "ads.example.com" {
				t.Errorf("qname = %v, want ads.example.com", got)
			}
			return
		}
	}
	t.Fatalf("no write-failure line captured: %v", obs.Captured(t))
}

// foldRecorder is a DecisionRecorder that keeps every call in order.
type foldRecorder struct{ rows [][3]string }

func (r *foldRecorder) Record(qname, action, matched string) {
	r.rows = append(r.rows, [3]string{qname, action, matched})
}

// foldResolver counts upstream calls so a row can tell forwarded from answered
// locally.
type foldResolver struct{ calls atomic.Int32 }

func (r *foldResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	r.calls.Add(1)
	return (&stubResolver{}).Query(ctx, req)
}
func (r *foldResolver) Address() string { return "127.0.0.1:9001" }

// foldOnceRow is one end-to-end case for TestHandleQuery_FoldOnce_RealLists.
type foldOnceRow struct {
	name                string
	query               string
	allow, block, decoy []string
	wantAction          string // recorder action: block | allow | decoy | forward
	wantQname           string // recorder qname (folded exactly once)
	wantMatched         string // recorder matched label
	wantMsg             string // policy log message; "" when no policy line is emitted
	wantForwarded       bool
}

// runFoldOnce builds a Server over real hostlist and decoy sets, sends one
// query through handleQuery and checks the recorder row, the upstream call
// count and the policy log line.
func runFoldOnce(t *testing.T, tc foldOnceRow) {
	t.Helper()
	restore := obs.Capture(t)
	defer restore()

	allow, err := hostlist.FromEntries(tc.allow)
	if err != nil {
		t.Fatalf("allow FromEntries: %v", err)
	}
	block, err := hostlist.FromEntries(tc.block)
	if err != nil {
		t.Fatalf("block FromEntries: %v", err)
	}
	decoys, err := decoy.FromEntries(tc.decoy)
	if err != nil {
		t.Fatalf("decoy FromEntries: %v", err)
	}
	rec, up := &foldRecorder{}, &foldResolver{}
	srv, err := NewServer(Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []Resolver{up},
		QueryTimeout:    2 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          policy.NewEngine(allow, block),
		Decoys:          decoys,
		Decisions:       rec,
		BlockResponse: config.BlockResponseConfig{
			Mode: config.BlockResponseModeAddress,
			A:    netip.MustParseAddr("0.0.0.0"),
			AAAA: netip.MustParseAddr("::"),
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion(tc.query, dns.TypeA)
	raddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	srv.handleQuery(&stubResponseWriter{remoteAddr: raddr}, req)

	if want := [][3]string{{tc.wantQname, tc.wantAction, tc.wantMatched}}; len(rec.rows) != 1 || rec.rows[0] != want[0] {
		t.Errorf("recorder rows = %v, want %v", rec.rows, want)
	}
	if got := up.calls.Load() > 0; got != tc.wantForwarded {
		t.Errorf("forwarded = %v, want %v", got, tc.wantForwarded)
	}
	checkFoldOnceLog(t, tc, obs.Captured(t))
}

// checkFoldOnceLog asserts the policy log line (message, qname, matched and,
// for a block, the remediation) or its absence.
func checkFoldOnceLog(t *testing.T, tc foldOnceRow, records []map[string]any) {
	t.Helper()
	var got map[string]any
	for _, r := range records {
		if msg, _ := r["msg"].(string); strings.HasPrefix(msg, "policy: ") {
			got = r
		}
	}
	if tc.wantMsg == "" {
		if got != nil {
			t.Errorf("unexpected policy line: %v", got)
		}
		return
	}
	if got == nil || got["msg"] != tc.wantMsg {
		t.Fatalf("policy line = %v, want msg %q", got, tc.wantMsg)
	}
	if got["qname"] != tc.wantQname || got["matched"] != tc.wantMatched {
		t.Errorf("qname/matched = %v/%v, want %s/%s", got["qname"], got["matched"], tc.wantQname, tc.wantMatched)
	}
	if tc.wantAction == "block" {
		if got["kind"] != "block" || got["list_id"] == nil || got["remediation"] != "add to allowlist: "+tc.wantQname {
			t.Errorf("block attribution fields wrong: %v", got)
		}
	}
}

// TestHandleQuery_FoldOnce_RealLists pins that the dataplane's single fold is
// enough: mixed-case, trailing-dot names reach real hostlist and decoy sets
// folded, so block, allow and decoy entries still match end to end.
// Serial: swaps slog.Default through obs.Capture to assert on log records.
func TestHandleQuery_FoldOnce_RealLists(t *testing.T) {
	cases := []foldOnceRow{
		{
			name: "block", query: "ADS.Example.COM.", block: []string{"example.com"},
			wantAction: "block", wantQname: "ads.example.com", wantMatched: "example.com",
			wantMsg: "policy: blocked",
		},
		{
			name: "allow_beats_block", query: "Good.Example.COM.",
			allow: []string{"good.example.com"}, block: []string{"example.com"},
			wantAction: "allow", wantQname: "good.example.com", wantMatched: "good.example.com",
			wantMsg: "policy: allowed", wantForwarded: true,
		},
		{
			name: "decoy_beats_allow", query: "TRAP.Example.COM.",
			decoy: []string{"trap.example.com"}, allow: []string{"trap.example.com"},
			wantAction: "decoy", wantQname: "trap.example.com", wantMatched: "trap.example.com",
			wantMsg: "policy: alert",
		},
		{
			name: "miss", query: "NotHere.Unlisted.ORG.",
			wantAction: "forward", wantQname: "nothere.unlisted.org", wantForwarded: true,
		},
		// The probes of an escaped-dot name all contain a backslash, which
		// NormalizeName rejects in every entry, so this is a miss both before
		// and after the matchers stop folding.
		{
			name: "escaped_dot", query: "example.com\\..",
			block: []string{"example.com", "com"}, decoy: []string{"example.com"},
			wantAction: "forward", wantQname: "example.com\\.", wantForwarded: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { runFoldOnce(t, tc) })
	}
}

// maliciousClassifier flags every name, so the async path always reaches
// DecideWithVerdict and logs a `policy: classified` record.
type maliciousClassifier struct{}

func (maliciousClassifier) Classify(context.Context, model.Input) (schema.Verdict, error) {
	return schema.VerdictMalicious, nil
}

// TestHandleQuery_FoldOnce_AsyncClassifierMixedCase pins that classifyAsync
// gets the folded name even with no trailing dot to strip. A name that missed
// the lists is forwarded, so the observable is the record's qname: a case-only
// regression would hand DecideWithVerdict (and the log) the mixed-case name.
// Serial: swaps slog.Default through obs.Capture to assert on log records.
func TestHandleQuery_FoldOnce_AsyncClassifierMixedCase(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	srv, err := NewServer(Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []Resolver{&stubResolver{}},
		QueryTimeout:    time.Second,
		ShutdownTimeout: time.Second,
		Engine:          policy.NewEngine(nil, nil),
		Classifier:      maliciousClassifier{},
		BlockResponse: config.BlockResponseConfig{
			Mode: config.BlockResponseModeAddress,
			A:    netip.MustParseAddr("0.0.0.0"),
			AAAA: netip.MustParseAddr("::"),
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("ADS.Example.COM", dns.TypeA)
	raddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	srv.handleQuery(&stubResponseWriter{remoteAddr: raddr}, req)
	srv.inFlight.Wait()

	for _, r := range obs.Captured(t) {
		if r["msg"] != "policy: classified" {
			continue
		}
		if r["qname"] != "ads.example.com" || r["matched"] != "(model)" {
			t.Errorf("classified record = %v, want qname ads.example.com, matched (model)", r)
		}
		return
	}
	t.Fatal("no `policy: classified` record")
}
