// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
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
	ln, lerr := rebindTCP(addr)
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
	pc, perr := rebindUDP(addr)
	if perr != nil {
		t.Fatalf("udp %s still bound after Serve returned: %v", addr, perr)
	}
	_ = pc.Close()
}

// stubListener is a net.Listener that never binds anything.
type stubListener struct{ addr net.Addr }

func (stubListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (stubListener) Close() error              { return nil }
func (l stubListener) Addr() net.Addr          { return l.addr }

// rebindTCP and rebindUDP re-bind addr to prove a port was released. Another
// test may grab a just-freed ephemeral port, so each retries once after a
// short sleep.
func rebindTCP(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		time.Sleep(50 * time.Millisecond)
		ln, err = net.Listen("tcp", addr)
	}
	return ln, err
}

func rebindUDP(addr string) (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		time.Sleep(50 * time.Millisecond)
		pc, err = net.ListenPacket("udp", addr)
	}
	return pc, err
}

func TestBind_TCPTwinRetry(t *testing.T) {
	inUse := fmt.Errorf("listen tcp: %w", syscall.EADDRINUSE)
	denied := fmt.Errorf("listen tcp: %w", syscall.EACCES)
	cases := []struct {
		name       string
		listenAddr string
		failFirst  int   // listenTCP calls that fail before one succeeds
		failWith   error // error those calls return
		wantCalls  int32
		wantErr    error // nil: bind must succeed
	}{
		{"ephemeral_retries_until_free", "127.0.0.1:0", 2, inUse, 3, nil},
		{"ephemeral_gives_up_after_bindAttempts", "127.0.0.1:0", 1 << 30, inUse, bindAttempts, syscall.EADDRINUSE},
		{"fixed_port_never_retries", "127.0.0.1:5354", 1 << 30, inUse, 1, syscall.EADDRINUSE},
		{"other_errors_never_retry", "127.0.0.1:0", 1 << 30, denied, 1, syscall.EACCES},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServeTestServer(t, tc.listenAddr)
			// Never bind a real fixed port: every UDP bind goes to an
			// ephemeral loopback port, and each one is recorded so the test
			// can prove bind closed it again.
			var udpAddrs []string
			srv.listenUDP = func(network, _ string) (net.PacketConn, error) {
				pc, err := net.ListenPacket(network, "127.0.0.1:0")
				if err == nil {
					udpAddrs = append(udpAddrs, pc.LocalAddr().String())
				}
				return pc, err
			}
			var calls atomic.Int32
			srv.listenTCP = func(network, address string) (net.Listener, error) {
				if int(calls.Add(1)) <= tc.failFirst {
					return nil, tc.failWith
				}
				// Success attempt: a stub, so no real TCP bind can collide.
				ta, err := net.ResolveTCPAddr(network, address)
				if err != nil {
					return nil, err
				}
				return stubListener{addr: ta}, nil
			}

			pc, ln, err := srv.bind()
			if got := calls.Load(); got != tc.wantCalls {
				t.Errorf("listenTCP calls = %d; want %d", got, tc.wantCalls)
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("bind: %v", err)
				}
				defer pc.Close()
				defer ln.Close()
				if pc.LocalAddr().String() != ln.Addr().String() {
					t.Errorf("udp %s and tcp %s differ", pc.LocalAddr(), ln.Addr())
				}
				udpAddrs = udpAddrs[:len(udpAddrs)-1] // the kept socket
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("bind = %v; want an error wrapping %v", err, tc.wantErr)
			}
			for _, a := range udpAddrs {
				c, err := rebindUDP(a)
				if err != nil {
					t.Errorf("udp socket %s from a failed attempt was not closed: %v", a, err)
					continue
				}
				_ = c.Close()
			}
		})
	}
}
