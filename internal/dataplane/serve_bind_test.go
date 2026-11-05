// SPDX-License-Identifier: Apache-2.0

package dataplane_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/dataplane"
	"protocolward.ai/ward/internal/obs"
)

// newBindTestServer returns an unstarted Server on listenAddr.
func newBindTestServer(t *testing.T, listenAddr string) *dataplane.Server {
	t.Helper()
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      listenAddr,
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}},
		QueryTimeout:    2 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func TestServe_ShutdownAfterReady_ReturnsNil(t *testing.T) {
	t.Parallel()
	srv := newBindTestServer(t, "127.0.0.1:0")
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve() }()
	if _, err := waitForAddr(srv, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve after Shutdown = %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return within 2s of Shutdown")
	}
}

// serveWithin runs srv.Serve and returns its error. It fails the test if
// Serve has not returned within d.
func serveWithin(t *testing.T, srv *dataplane.Server, d time.Duration) error {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve() }()
	select {
	case err := <-errCh:
		return err
	case <-time.After(d):
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		t.Fatalf("Serve did not return within %s", d)
		return nil
	}
}

func TestServe_UDPPortTaken_ReturnsBindError(t *testing.T) {
	t.Parallel()
	held, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-bind udp: %v", err)
	}
	defer held.Close()
	addr := held.LocalAddr().String()

	err = serveWithin(t, newBindTestServer(t, addr), 2*time.Second)
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("Serve = %v; want an error wrapping EADDRINUSE", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "udp") || !strings.Contains(msg, addr) {
		t.Errorf("Serve error %q should name udp and %s", msg, addr)
	}
}

func listeningLines(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range obs.Captured(t) {
		if r["msg"] == "dns: listening" {
			out = append(out, r)
		}
	}
	return out
}

// The readiness line is logged once, after both UDP and TCP serve, with the
// bound address. Scripts key on it instead of a line logged before bind.
// Serial: swaps slog.Default through obs.Capture to assert on log records.
func TestServe_LogsListeningOnceBothListenersServe(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	srv := newBindTestServer(t, "127.0.0.1:0")
	go func() { _ = srv.Serve() }()
	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	defer func() { _ = srv.Shutdown(ctx) }()

	lines := listeningLines(t)
	if len(lines) != 1 {
		t.Fatalf("dns: listening lines = %d; want 1", len(lines))
	}
	if lines[0]["addr"] != addr {
		t.Errorf("dns: listening addr = %v; want %s", lines[0]["addr"], addr)
	}
}

// Listening is closed once both listeners serve, and never on a bind failure.
// Serial: the second subtest holds a loopback port for its whole run.
func TestServer_Listening(t *testing.T) {
	t.Run("closed once both serve", func(t *testing.T) {
		srv := newBindTestServer(t, "127.0.0.1:0")
		select {
		case <-srv.Listening():
			t.Fatal("Listening closed before Serve")
		default:
		}
		go func() { _ = srv.Serve() }()
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		})
		select {
		case <-srv.Listening():
		case <-time.After(2 * time.Second):
			t.Fatal("Listening not closed within 2s of Serve")
		}
		if srv.Addr() == "" {
			t.Error("Addr empty after Listening closed")
		}
		first, second := srv.Listening(), srv.Listening()
		if first != second {
			t.Error("Listening returned different channels")
		}
	})
	t.Run("never closed on a bind failure", func(t *testing.T) {
		held, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("pre-bind udp: %v", err)
		}
		defer held.Close()
		srv := newBindTestServer(t, held.LocalAddr().String())
		err = serveWithin(t, srv, 2*time.Second)
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("Serve = %v; want an error wrapping EADDRINUSE", err)
		}
		select {
		case <-srv.Listening():
			t.Fatal("Listening closed although Serve failed to bind")
		default:
		}
	})
}
