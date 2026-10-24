// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
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
)

var sinkWritten *dns.Msg

// BenchmarkHandleQuery measures one handleQuery call through the stub writer.
// forward_no_classifier is the fast path only: no Classifier is configured, so
// the slow-path fork is not measured.
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

	cases := []struct {
		name   string
		qname  string
		verify func(m *dns.Msg) string
	}{
		{"forward_no_classifier", "nothere.unlisted.org.", func(m *dns.Msg) string {
			if m.Rcode != dns.RcodeSuccess {
				return fmt.Sprintf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
			}
			// A block response sets AA and carries one answer; the stub
			// resolver reply has neither, so this proves the upstream path ran.
			if len(m.Answer) != 0 || m.Authoritative {
				return fmt.Sprintf("answers = %d, authoritative = %v, want a stub upstream reply (0, false)", len(m.Answer), m.Authoritative)
			}
			return ""
		}},
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
}
