// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/config"
	"protocolward.ai/ward/internal/decoy"
	"protocolward.ai/ward/internal/hostlist"
	"protocolward.ai/ward/internal/policy"
	"protocolward.ai/ward/internal/web"
	"protocolward.ai/ward/pkg/detect"
	"protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

// assessorProbe has the same value as dgaProbe in flags_test.go (package
// dataplane_test, out of reach from here): an md5-family DGA shape that
// detect.New() flags as malicious. If the precondition in
// forward_with_assessor fails, pick a malicious golden row from pkg/detect.
const assessorProbe = "3f9a1c7e5b2d8046af1e9c3b7d5a2e80.info"

var sinkWritten *dns.Msg

// BenchmarkHandleQuery measures one handleQuery call through the stub writer.
// forward_no_classifier is the fast path only: no Classifier is configured, so
// the slow-path fork is not measured. forward_with_assessor wires the
// in-process `pkg/detect` assessor and a FlagLog, as `ward serve` does for
// `model: builtin: lexical`, so each forwarded query also pays for
// `clientHost`, the `classifySlots` select, and either a goroutine fork or a
// counted drop (`drops/op`, the fraction of timed queries that took the drop
// branch instead of forking). Each round builds its own server and drains it
// with Shutdown in `b.Cleanup`. ns/op is the handler's own time (Assess runs
// on other Ps); B/op and allocs/op are process-wide and include forks that
// finished in the timed window; with one P most queries drop.
//
// The server is wired as in `ward serve`: policy engine, decoys and the
// dashboard decision recorder (web.NewStore).
//
// Logging is swapped for a JSON handler on io.Discard at Info, the cost of the
// production default. The swap is restored with b.Cleanup. testing runs
// benchmarks only after every test has finished and runs sub-benchmarks one at
// a time, so the swap cannot race; b.RunParallel is deliberately not used.
func BenchmarkHandleQuery(b *testing.B) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})))
	b.Cleanup(func() { slog.SetDefault(prev) })

	allowNames := make([]string, 1_000)
	for i := range allowNames {
		allowNames[i] = fmt.Sprintf("allow%04d.net", i)
	}
	blockNames := make([]string, 100_000)
	for i := range blockNames {
		blockNames[i] = fmt.Sprintf("host%06d.zone%02d.com", i, i%97)
	}
	decoyNames := make([]string, 1_000)
	for i := range decoyNames {
		decoyNames[i] = fmt.Sprintf("decoy%04d.corp-internal.com", i)
	}
	allow, err := hostlist.FromEntries(allowNames)
	if err != nil {
		b.Fatalf("allow FromEntries: %v", err)
	}
	block, err := hostlist.FromEntries(blockNames)
	if err != nil {
		b.Fatalf("block FromEntries: %v", err)
	}
	decoys, err := decoy.FromEntries(decoyNames)
	if err != nil {
		b.Fatalf("decoy FromEntries: %v", err)
	}
	srv, err := NewServer(Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []Resolver{&stubResolver{}},
		QueryTimeout:    2 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Engine:          policy.NewEngine(allow, block),
		Decoys:          decoys,
		Decisions:       web.NewStore(),
		BlockResponse: config.BlockResponseConfig{
			Mode: config.BlockResponseModeAddress,
			A:    netip.MustParseAddr("0.0.0.0"),
			AAAA: netip.MustParseAddr("::"),
		},
	})
	if err != nil {
		b.Fatalf("NewServer: %v", err)
	}

	raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	if err != nil {
		b.Fatalf("resolve: %v", err)
	}

	// wantZeroA asserts a single 0.0.0.0 A answer with NOERROR.
	wantZeroA := func(m *dns.Msg) string {
		if m.Rcode != dns.RcodeSuccess {
			return fmt.Sprintf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
		}
		if len(m.Answer) != 1 {
			return fmt.Sprintf("answers = %d, want 1", len(m.Answer))
		}
		a, ok := m.Answer[0].(*dns.A)
		if !ok {
			return fmt.Sprintf("answer type = %T, want *dns.A", m.Answer[0])
		}
		if !a.A.Equal(net.IPv4zero) {
			return fmt.Sprintf("answer ip = %s, want 0.0.0.0", a.A)
		}
		return ""
	}

	// wantStubForward asserts the stub upstream reply: NOERROR, no answers and
	// no AA bit. A block response sets AA and carries one answer, so this
	// proves the upstream path ran.
	wantStubForward := func(m *dns.Msg) string {
		if m.Rcode != dns.RcodeSuccess {
			return fmt.Sprintf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
		}
		if len(m.Answer) != 0 || m.Authoritative {
			return fmt.Sprintf("answers = %d, authoritative = %v, want a stub upstream reply (0, false)", len(m.Answer), m.Authoritative)
		}
		return ""
	}

	cases := []struct {
		name   string
		qname  string
		verify func(m *dns.Msg) string
	}{
		{"forward_no_classifier", "nothere.unlisted.org.", wantStubForward},
		{"block", "host000042.zone42.com.", wantZeroA},
		{"decoy", "decoy0042.corp-internal.com.", wantZeroA},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			req := new(dns.Msg)
			req.SetQuestion(tc.qname, dns.TypeA)
			req.RecursionDesired = true
			w := &stubResponseWriter{remoteAddr: raddr}

			srv.handleQuery(w, req)
			if w.written == nil {
				b.Fatal("handleQuery wrote no response")
			}
			if msg := tc.verify(w.written); msg != "" {
				b.Fatalf("%s: %s", tc.qname, msg)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				srv.handleQuery(w, req)
			}
			sinkWritten = w.written
		})
	}

	b.Run("forward_with_assessor", func(b *testing.B) {
		flags := web.NewFlagLog()
		asrv, err := NewServer(Config{
			ListenAddr:      "127.0.0.1:0",
			Resolvers:       []Resolver{&stubResolver{}},
			QueryTimeout:    2 * time.Second,
			ShutdownTimeout: 2 * time.Second,
			Engine:          policy.NewEngine(allow, block),
			Decoys:          decoys,
			Decisions:       web.NewStore(),
			Classifier:      detect.New(),
			Flags:           flags,
			BlockResponse: config.BlockResponseConfig{
				Mode: config.BlockResponseModeAddress,
				A:    netip.MustParseAddr("0.0.0.0"),
				AAAA: netip.MustParseAddr("::"),
			},
		})
		if err != nil {
			b.Fatalf("NewServer: %v", err)
		}
		// The server is never bound, so Shutdown's listener errors are
		// expected; only a drain timeout is a failure. Draining here keeps
		// forked classifications from leaking into later rounds.
		b.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := asrv.Shutdown(ctx); errors.Is(err, ErrDrainTimeout) {
				b.Errorf("Shutdown: %v", err)
			}
		})

		a, err := detect.New().Assess(context.Background(), model.Input{Hostname: assessorProbe})
		if err != nil || a.Verdict != schema.VerdictMalicious {
			b.Fatalf("precondition: detect.New() must flag %q as malicious, got %+v err=%v; pick a malicious golden row from pkg/detect", assessorProbe, a, err)
		}

		// The probe is forwarded, not blocked (flag-only), so it replies
		// like the stub upstream.
		probe := new(dns.Msg)
		probe.SetQuestion(assessorProbe+".", dns.TypeA)
		probe.RecursionDesired = true
		pw := &stubResponseWriter{remoteAddr: raddr}
		asrv.handleQuery(pw, probe)
		if pw.written == nil {
			b.Fatal("handleQuery wrote no response for the probe")
		}
		if msg := wantStubForward(pw.written); msg != "" {
			b.Fatalf("%s: %s", assessorProbe, msg)
		}
		asrv.inFlight.Wait()
		if got := flags.Snapshot(); len(got) != 1 || got[0].Qname != assessorProbe {
			b.Fatalf("the in-process assessor did not run: flags = %+v, want exactly one for %q", got, assessorProbe)
		}

		req := new(dns.Msg)
		req.SetQuestion("nothere.unlisted.org.", dns.TypeA)
		req.RecursionDesired = true
		w := &stubResponseWriter{remoteAddr: raddr}
		asrv.handleQuery(w, req)
		if w.written == nil {
			b.Fatal("handleQuery wrote no response")
		}
		if msg := wantStubForward(w.written); msg != "" {
			b.Fatalf("nothere.unlisted.org.: %s", msg)
		}

		b.ReportAllocs()
		droppedBefore := asrv.ClassifyDropped()
		b.ResetTimer()
		for range b.N {
			asrv.handleQuery(w, req)
		}
		b.StopTimer()
		b.ReportMetric(float64(asrv.ClassifyDropped()-droppedBefore)/float64(b.N), "drops/op")
		sinkWritten = w.written
	})
}
