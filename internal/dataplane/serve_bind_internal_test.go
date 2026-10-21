// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func newServeTestServer(t *testing.T, listenAddr string) *Server {
	t.Helper()
	srv, err := NewServer(Config{
		ListenAddr:      listenAddr,
		Resolvers:       []Resolver{&stubResolver{}},
		QueryTimeout:    2 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

// startServe runs srv.Serve, waits until both listeners serve, and returns
// the address plus Serve's result channel.
func startServe(t *testing.T, srv *Server) (string, <-chan error) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve() }()
	select {
	case <-srv.addrCh:
	case err := <-errCh:
		t.Fatalf("Serve returned before ready: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("server not ready within 2s")
	}
	return srv.Addr(), errCh
}

func waitServeErr(t *testing.T, errCh <-chan error) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return within 2s of the listener failing")
		return nil
	}
}

func TestServe_UDPListenerErrorAfterReady_StopsTCPAndReturnsError(t *testing.T) {
	srv := newServeTestServer(t, "127.0.0.1:0")
	addr, errCh := startServe(t, srv)

	_ = srv.udpSrv.PacketConn.Close() // simulate the UDP socket dying

	err := waitServeErr(t, errCh)
	if !errors.Is(err, net.ErrClosed) || !strings.Contains(err.Error(), "udp") {
		t.Fatalf("Serve = %v; want a udp error wrapping net.ErrClosed", err)
	}
	ln, lerr := net.Listen("tcp", addr)
	if lerr != nil {
		t.Fatalf("tcp %s still bound after Serve returned: %v", addr, lerr)
	}
	_ = ln.Close()
}

func TestServe_TCPListenerErrorAfterReady_StopsUDPAndReturnsError(t *testing.T) {
	srv := newServeTestServer(t, "127.0.0.1:0")
	addr, errCh := startServe(t, srv)

	_ = srv.tcpSrv.Listener.Close() // simulate the TCP listener dying

	err := waitServeErr(t, errCh)
	if !errors.Is(err, net.ErrClosed) || !strings.Contains(err.Error(), "tcp") {
		t.Fatalf("Serve = %v; want a tcp error wrapping net.ErrClosed", err)
	}
	pc, perr := net.ListenPacket("udp", addr)
	if perr != nil {
		t.Fatalf("udp %s still bound after Serve returned: %v", addr, perr)
	}
	_ = pc.Close()
}
