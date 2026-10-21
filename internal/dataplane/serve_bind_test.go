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

// takeTCPPortWithFreeUDP holds a TCP listener on an ephemeral loopback port
// whose UDP twin is free right now, so Serve's UDP bind succeeds and its TCP
// bind fails. The kernel picks TCP and UDP ports independently, hence the
// retry. The listener is closed by t.Cleanup.
func takeTCPPortWithFreeUDP(t *testing.T) string {
	t.Helper()
	for range 20 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("pre-bind tcp: %v", err)
		}
		addr := ln.Addr().String()
		if pc, err := net.ListenPacket("udp", addr); err == nil {
			_ = pc.Close()
			t.Cleanup(func() { _ = ln.Close() })
			return addr
		}
		_ = ln.Close()
	}
	t.Fatal("no loopback port with a free UDP twin in 20 tries")
	return ""
}

func TestServe_UDPPortTaken_ReturnsBindError(t *testing.T) {
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

func TestServe_TCPPortTaken_ReturnsBindErrorAndReleasesUDP(t *testing.T) {
	addr := takeTCPPortWithFreeUDP(t)

	err := serveWithin(t, newBindTestServer(t, addr), 2*time.Second)
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("Serve = %v; want an error wrapping EADDRINUSE", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "tcp") || !strings.Contains(msg, addr) {
		t.Errorf("Serve error %q should name tcp and %s", msg, addr)
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("udp %s still bound after Serve returned: %v", addr, err)
	}
	_ = pc.Close()
}
