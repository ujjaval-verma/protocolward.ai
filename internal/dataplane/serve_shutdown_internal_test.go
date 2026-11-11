// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/obs"
)

// gateResolver holds its first query until release is closed: entered is
// closed once that query arrives, so a test knows a reply is in flight.
type gateResolver struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (g *gateResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	g.once.Do(func() { close(g.entered) })
	select {
	case <-g.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	m := new(dns.Msg)
	return m.SetReply(req), nil
}

func (g *gateResolver) Address() string { return "127.0.0.1:9" }

// newGateServer returns an unstarted Server on an ephemeral loopback port
// whose only resolver is a fresh gateResolver.
func newGateServer(t *testing.T) (*Server, *gateResolver) {
	t.Helper()
	gate := &gateResolver{entered: make(chan struct{}), release: make(chan struct{})}
	srv, err := NewServer(Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []Resolver{gate},
		QueryTimeout:    5 * time.Second,
		ShutdownTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, gate
}

type queryResult struct {
	msg *dns.Msg
	err error
}

// heldQuery starts srv, sends one UDP A query and waits until the gate holds
// it. It returns Serve's result channel and the query's reply channel.
func heldQuery(t *testing.T, srv *Server, gate *gateResolver) (<-chan error, <-chan queryResult) {
	t.Helper()
	addr, serveErr := startServe(t, srv)
	reply := make(chan queryResult, 1)
	go func() {
		c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
		m := new(dns.Msg)
		m.SetQuestion("held.example.", dns.TypeA)
		r, _, err := c.Exchange(m, addr)
		reply <- queryResult{r, err}
	}()
	select {
	case <-gate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("query did not reach the resolver within 2s")
	}
	return serveErr, reply
}

// shutAsync runs srv.Shutdown with a 3 s context in a goroutine and returns
// its result channel.
func shutAsync(srv *Server) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		errCh <- srv.Shutdown(ctx)
	}()
	return errCh
}

// waitShutdown returns the result of a shutAsync call, failing the test if
// it has not arrived within 4 s.
func waitShutdown(t *testing.T, name string, errCh <-chan error) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(4 * time.Second):
		t.Fatalf("Shutdown %s did not return within 4s", name)
		return nil
	}
}

// waitReply returns the held query's reply, failing the test if the client
// has not finished within 4 s (its own timeout is 3 s).
func waitReply(t *testing.T, reply <-chan queryResult) queryResult {
	t.Helper()
	select {
	case r := <-reply:
		return r
	case <-time.After(4 * time.Second):
		t.Fatal("query client did not finish within 4s")
		return queryResult{}
	}
}

// A second Shutdown while the first is draining an in-flight UDP query must
// not close the socket that query's reply is written to.
func TestShutdown_SecondCallDuringDrain_KeepsReplySocket(t *testing.T) {
	t.Parallel()
	srv, gate := newGateServer(t)
	serveErr, reply := heldQuery(t, srv, gate)

	first := shutAsync(srv)
	time.Sleep(50 * time.Millisecond) // #1 stops both transports and starts draining
	second := shutAsync(srv)
	time.Sleep(50 * time.Millisecond) // #2 has run whatever it runs before draining
	close(gate.release)

	if r := waitReply(t, reply); r.err != nil {
		t.Fatalf("in-flight query got no reply: %v", r.err)
	}
	waitShutdown(t, "#1", first)
	waitShutdown(t, "#2", second)
	if err := waitServeErr(t, serveErr); err != nil {
		t.Fatalf("Serve = %v; want nil", err)
	}
}

// serveBounded runs srv.Serve and returns its error. It fails the test if
// Serve has not returned within 1 s. It is the internal-package twin of
// serveWithin in serve_bind_test.go.
func serveBounded(t *testing.T, srv *Server) error {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve() }()
	select {
	case err := <-errCh:
		return err
	case <-time.After(time.Second):
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		t.Fatal("Serve did not return within 1s")
		return nil
	}
}

// Serial: obs.Capture swaps the global slog default.
func TestServe_ShutdownBetweenBindAndActivate_ReturnsNil(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	srv := newServeTestServer(t, "127.0.0.1:0")
	// A non-*net.UDPConn makes miekg skip setUDPSocketOptions, which on
	// Linux fails on the closed socket before NotifyStartedFunc; with the
	// wrapper UDP's late activation reaches listenerStarted on every OS.
	srv.listenUDP = func(n, a string) (net.PacketConn, error) {
		pc, err := net.ListenPacket(n, a)
		if err != nil {
			return nil, err
		}
		return struct{ net.PacketConn }{pc}, nil
	}
	var shutErr error
	srv.beforeActivate = func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		shutErr = srv.Shutdown(ctx)
	}

	if err := serveBounded(t, srv); err != nil {
		t.Fatalf("Serve = %v; want nil", err)
	}
	if !errors.Is(shutErr, ErrNotStarted) {
		t.Errorf("Shutdown between bind and activation = %v; want an error wrapping ErrNotStarted", shutErr)
	}

	records := map[string]map[string]any{}
	for _, r := range obs.Captured(t) {
		if r["level"] == "DEBUG" && r["msg"] == "dataplane: listener stopped during shutdown" {
			transport, _ := r["transport"].(string)
			records[transport] = r
		}
	}
	if len(records) != 2 || records["udp"] == nil || records["tcp"] == nil {
		t.Fatalf("listener stopped during shutdown records = %v; want udp and tcp", records)
	}
	for transport, r := range records {
		for _, key := range []string{"addr", "error", "remediation"} {
			if v, _ := r[key].(string); v == "" {
				t.Errorf("%s record: %s is empty; want it set (record %v)", transport, key, r)
			}
		}
	}
	if lines := listeningLines(t); len(lines) != 0 {
		t.Errorf("dns: listening records = %v; want none (Shutdown began before readiness)", lines)
	}
	select {
	case <-srv.Listening():
		t.Error("Listening() is closed; want it open (Shutdown began before readiness)")
	default:
	}
	if got := srv.Addr(); got != "" {
		t.Errorf("Addr() = %q; want \"\" (Shutdown began before readiness)", got)
	}
}

// UDP activates and serves; Shutdown runs before TCP activates. Shutdown
// must report ErrNotStarted for tcp only, and readiness must never be
// announced although UDP was serving.
// Serial: obs.Capture swaps the global slog default.
func TestServe_ShutdownWithOnlyUDPServing_ReportsTCPNotStarted(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	srv := newServeTestServer(t, "127.0.0.1:0")
	udpUp := make(chan struct{})
	// miekg calls NotifyStartedFunc after it set UDP's started flag, so once
	// udpUp is closed a ShutdownContext on UDP is a real stop.
	srv.udpSrv.NotifyStartedFunc = func() {
		srv.listenerStarted()
		close(udpUp)
	}
	hookDone := make(chan struct{})
	var sawUDP bool
	var shutErr error
	srv.betweenActivate = func() {
		// Runs on the Serve goroutine, so it cannot fail the test; the test
		// goroutine reads sawUDP and shutErr after <-hookDone.
		defer close(hookDone)
		select {
		case <-udpUp:
			sawUDP = true
		case <-time.After(500 * time.Millisecond):
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		shutErr = srv.Shutdown(ctx)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	select {
	case <-hookDone:
	case <-time.After(2 * time.Second):
		t.Fatal("betweenActivate never ran")
	}
	if !sawUDP {
		t.Fatal("betweenActivate: UDP never reported started within 500ms")
	}
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve = %v; want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return within 1s of the hook finishing")
	}

	if !errors.Is(shutErr, ErrNotStarted) || errors.Is(shutErr, ErrDrainTimeout) {
		t.Errorf("Shutdown = %v; want an error wrapping ErrNotStarted and not ErrDrainTimeout", shutErr)
	}
	if shutErr != nil {
		if msg := shutErr.Error(); !strings.Contains(msg, "dataplane shutdown (tcp)") || strings.Contains(msg, "dataplane shutdown (udp)") {
			t.Errorf("Shutdown = %q; want a tcp error and no udp error (UDP was serving and stopped by miekg)", msg)
		}
	}

	var stoppedTransports []string
	for _, r := range obs.Captured(t) {
		if r["level"] == "DEBUG" && r["msg"] == "dataplane: listener stopped during shutdown" {
			transport, _ := r["transport"].(string)
			stoppedTransports = append(stoppedTransports, transport)
		}
	}
	if len(stoppedTransports) != 1 || stoppedTransports[0] != "tcp" {
		t.Errorf("listener stopped during shutdown records for transports %v; want exactly one, tcp", stoppedTransports)
	}
	if lines := listeningLines(t); len(lines) != 0 {
		t.Errorf("dns: listening records = %v; want none (Shutdown began before TCP activated)", lines)
	}
	select {
	case <-srv.Listening():
		t.Error("Listening() is closed; want it open (Shutdown began before readiness)")
	default:
	}
	if got := srv.Addr(); got != "" {
		t.Errorf("Addr() = %q; want \"\" (Shutdown began before readiness)", got)
	}
}

// The owner (the Shutdown that takes the sockets) pauses after the take
// while a second Shutdown runs and drains; the in-flight reply must still be
// written, so the paused owner must not close a socket under that drain.
func TestShutdown_OwnerPausedWhileOtherDrains_KeepsReplySocket(t *testing.T) {
	t.Parallel()
	srv, gate := newGateServer(t)
	serveErr, reply := heldQuery(t, srv, gate)

	// CompareAndSwap, not sync.Once: Once.Do would block B inside the hook
	// until A's hook returned, which hides the bug.
	var paused atomic.Bool
	var b <-chan error
	hookDone := make(chan struct{})
	srv.afterTake = func() {
		if !paused.CompareAndSwap(false, true) {
			return
		}
		b = shutAsync(srv)
		time.Sleep(100 * time.Millisecond) // B takes nothing and waits for A to stop the listeners
		close(hookDone)
	}

	a := shutAsync(srv)
	select {
	case <-hookDone:
	case <-time.After(4 * time.Second):
		t.Fatal("afterTake never ran")
	}
	time.Sleep(50 * time.Millisecond) // A resumes and reaches miekg's drain
	close(gate.release)

	if r := waitReply(t, reply); r.err != nil {
		t.Fatalf("in-flight query got no reply: %v", r.err)
	}
	if err := waitShutdown(t, "A", a); err != nil {
		t.Errorf("owner Shutdown A = %v; want nil", err)
	}
	if err := waitShutdown(t, "B", b); !errors.Is(err, ErrNotStarted) {
		t.Errorf("second Shutdown B = %v; want an error wrapping ErrNotStarted", err)
	}
	if err := waitServeErr(t, serveErr); err != nil {
		t.Fatalf("Serve = %v; want nil", err)
	}
}

func TestServe_StoppingChecks(t *testing.T) {
	t.Parallel()

	t.Run("shutdown before serve binds nothing", func(t *testing.T) {
		srv := newServeTestServer(t, "127.0.0.1:0")
		var binds atomic.Int32
		srv.listenUDP = func(network, address string) (net.PacketConn, error) {
			binds.Add(1)
			return net.ListenPacket(network, address)
		}
		_ = srv.Shutdown(context.Background())
		if err := serveBounded(t, srv); err != nil {
			t.Fatalf("Serve after Shutdown = %v; want nil", err)
		}
		if n := binds.Load(); n != 0 {
			t.Errorf("UDP binds = %d; want 0", n)
		}
	})

	t.Run("shutdown during bind closes the bound sockets", func(t *testing.T) {
		srv := newServeTestServer(t, "127.0.0.1:0")
		var pc net.PacketConn
		var ln *net.TCPListener
		srv.listenUDP = func(network, address string) (net.PacketConn, error) {
			p, err := net.ListenPacket(network, address)
			pc = p
			return p, err
		}
		srv.listenTCP = func(network, address string) (net.Listener, error) {
			_ = srv.Shutdown(context.Background())
			l, err := net.Listen(network, address)
			if err != nil {
				return nil, err
			}
			ln = l.(*net.TCPListener)
			return l, nil
		}
		if err := serveBounded(t, srv); err != nil {
			t.Fatalf("Serve = %v; want nil", err)
		}
		if err := pc.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
			t.Errorf("UDP socket after Serve: SetReadDeadline = %v; want net.ErrClosed (socket closed)", err)
		}
		if err := ln.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
			t.Errorf("TCP listener after Serve: SetDeadline = %v; want net.ErrClosed (listener closed)", err)
		}
	})

	t.Run("shutdown during bind, bind fails: bind error returned", func(t *testing.T) {
		srv := newServeTestServer(t, "127.0.0.1:0")
		srv.listenTCP = func(string, string) (net.Listener, error) {
			_ = srv.Shutdown(context.Background())
			return nil, fmt.Errorf("listen tcp: %w", syscall.EACCES)
		}
		if err := serveBounded(t, srv); !errors.Is(err, syscall.EACCES) {
			t.Fatalf("Serve = %v; want an error wrapping EACCES", err)
		}
	})
}

// A TCP listener that activates between miekg's "not started" answer and the
// owner's close must still be stopped: a live connection opened in that
// window would otherwise hold Serve for miekg's 8 s idle timeout.
func TestShutdown_TCPActivatesInNotStartedWindow_ServeReturnsWithin1s(t *testing.T) {
	t.Parallel()
	srv := newServeTestServer(t, "127.0.0.1:0")

	type held struct {
		conn *dns.Conn
		err  error
	}
	heldCh := make(chan held, 1)
	shutCh := make(chan error, 1)
	reached := make(chan struct{})
	var tcpAddr string
	srv.beforeActivate = func() {
		// Runs on the Serve goroutine, so it cannot fail the test; the test
		// goroutine reports a hook that never ran.
		tcpAddr = srv.tcpSrv.Listener.Addr().String()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			shutCh <- srv.Shutdown(ctx)
		}()
		select {
		case <-reached:
		case <-time.After(2 * time.Second):
		}
	}
	srv.afterNotStarted = func(transport string) {
		if transport != "tcp" {
			return
		}
		close(reached) // Serve now activates both transports
		c := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
		conn, err := c.Dial(tcpAddr)
		if err == nil {
			m := new(dns.Msg)
			m.SetQuestion("window.example.", dns.TypeA)
			_, _, err = c.ExchangeWithConn(m, conn)
		}
		heldCh <- held{conn, err}
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()

	var h held
	select {
	case h = <-heldCh:
	case <-time.After(4 * time.Second):
		t.Fatal("afterNotStarted(tcp) never ran")
	}
	if h.conn != nil {
		t.Cleanup(func() { _ = h.conn.Close() })
	}
	var shutErr error
	select {
	case shutErr = <-shutCh:
	case <-time.After(4 * time.Second):
		t.Fatal("Shutdown did not return within 4s")
	}
	if h.err != nil {
		t.Fatalf("query over the TCP connection opened in the window: %v; want a reply (TCP activated on the open listener)", h.err)
	}
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve = %v; want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return within 1s of Shutdown")
	}
	if !errors.Is(shutErr, ErrNotStarted) {
		t.Errorf("Shutdown = %v; want an error wrapping ErrNotStarted (UDP never activated)", shutErr)
	}
	if shutErr != nil && strings.Contains(shutErr.Error(), "dataplane shutdown (tcp)") {
		t.Errorf("Shutdown = %v; want no tcp error (the second ShutdownContext stopped TCP)", shutErr)
	}
}

// A Shutdown that does not own the listeners must not drain while the owner
// has taken them but not stopped them yet: queries are still being served,
// so its drain could start before they are counted.
func TestShutdown_SecondCallWaitsForOwnerToStopListeners(t *testing.T) {
	t.Parallel()

	// pauseOwner starts Shutdown A on a serving srv and returns once A has
	// taken the sockets and paused before any miekg call. Both listeners
	// still serve then.
	pauseOwner := func(t *testing.T) (srv *Server, addr string, serveErr, a <-chan error, resume func()) {
		t.Helper()
		srv = newServeTestServer(t, "127.0.0.1:0")
		addr, serveErr = startServe(t, srv)
		paused := make(chan struct{})
		resumeCh := make(chan struct{})
		var once sync.Once
		resume = func() { once.Do(func() { close(resumeCh) }) }
		t.Cleanup(resume)
		// CompareAndSwap, not sync.Once: only the first caller (the owner)
		// pauses, and later callers must not block inside the hook.
		var first atomic.Bool
		srv.afterTake = func() {
			if !first.CompareAndSwap(false, true) {
				return
			}
			close(paused)
			select {
			case <-resumeCh:
			case <-time.After(5 * time.Second):
			}
		}
		a = shutAsync(srv)
		select {
		case <-paused:
		case <-time.After(2 * time.Second):
			t.Fatal("afterTake never paused the owner")
		}
		return srv, addr, serveErr, a, resume
	}

	t.Run("query during the pause gets its reply", func(t *testing.T) {
		t.Parallel()
		srv, addr, serveErr, a, resume := pauseOwner(t)
		b := shutAsync(srv)

		c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
		m := new(dns.Msg)
		m.SetQuestion("paused.example.", dns.TypeA)
		if _, _, err := c.Exchange(m, addr); err != nil {
			t.Fatalf("query during the owner's pause: %v; want a reply (the listeners still serve)", err)
		}
		select {
		case err := <-b:
			t.Fatalf("second Shutdown returned while the owner was paused before stopping the listeners: %v", err)
		case <-time.After(200 * time.Millisecond):
		}

		resume()
		if err := waitShutdown(t, "A", a); err != nil {
			t.Errorf("owner Shutdown A = %v; want nil", err)
		}
		if err := waitShutdown(t, "B", b); !errors.Is(err, ErrNotStarted) || errors.Is(err, ErrDrainTimeout) {
			t.Errorf("second Shutdown B = %v; want an error wrapping ErrNotStarted and not ErrDrainTimeout", err)
		}
		if err := waitServeErr(t, serveErr); err != nil {
			t.Fatalf("Serve = %v; want nil", err)
		}
	})

	t.Run("ctx ends first: drain timeout", func(t *testing.T) {
		t.Parallel()
		srv, _, serveErr, a, resume := pauseOwner(t)
		b := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			b <- srv.Shutdown(ctx)
		}()

		var err error
		select {
		case err = <-b:
		case <-time.After(2 * time.Second):
			t.Fatal("second Shutdown did not return within 2s of its 100ms ctx while the owner was paused")
		}
		if !errors.Is(err, ErrDrainTimeout) {
			t.Errorf("second Shutdown = %v; want an error wrapping ErrDrainTimeout", err)
		}
		if !errors.Is(err, ErrNotStarted) {
			t.Errorf("second Shutdown = %v; want it to also wrap ErrNotStarted (it stopped no listener)", err)
		}
		if err != nil {
			drainLine := strings.SplitN(err.Error(), "\n", 2)[0] // errors.Join puts the drain error first
			if !strings.Contains(drainLine, "while waiting for another Shutdown call to stop the listeners") ||
				!strings.Contains(drainLine, "remediation:") || strings.Contains(drainLine, "classification(s)") {
				t.Errorf("drain error %q; want it to say it was waiting for another Shutdown call to stop the listeners, name a remediation and give no classification count", drainLine)
			}
		}

		resume()
		if err := waitShutdown(t, "A", a); err != nil {
			t.Errorf("owner Shutdown A = %v; want nil", err)
		}
		if err := waitServeErr(t, serveErr); err != nil {
			t.Fatalf("Serve = %v; want nil", err)
		}
	})

	t.Run("owner held after it began stopping", func(t *testing.T) {
		t.Parallel()
		// The owner A is held inside afterNotStarted("tcp"): it has run
		// miekg for UDP and for TCP's first answer, but has not finished
		// stopping. TCP can activate on the still-open listener meanwhile.
		srv := newServeTestServer(t, "127.0.0.1:0")
		held := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		releaseA := func() { once.Do(func() { close(release) }) }
		t.Cleanup(releaseA)
		a := make(chan error, 1)
		var b <-chan error
		srv.beforeActivate = func() {
			// Runs on the Serve goroutine, so it cannot fail the test.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				a <- srv.Shutdown(ctx)
			}()
			select {
			case <-held:
			case <-time.After(2 * time.Second):
			}
		}
		srv.afterNotStarted = func(transport string) {
			if transport != "tcp" {
				return
			}
			b = shutAsync(srv)
			close(held)
			select {
			case <-release:
			case <-time.After(2 * time.Second):
			}
		}

		serveErr := make(chan error, 1)
		go func() { serveErr <- srv.Serve() }()
		select {
		case <-held:
		case <-time.After(4 * time.Second):
			t.Fatal("afterNotStarted(tcp) never held the owner")
		}
		select {
		case err := <-b:
			t.Fatalf("second Shutdown returned while the owner was held after it began stopping: %v", err)
		case <-time.After(200 * time.Millisecond):
		}

		releaseA()
		if err := waitShutdown(t, "A", a); !errors.Is(err, ErrNotStarted) {
			t.Errorf("owner Shutdown A = %v; want an error wrapping ErrNotStarted (UDP never activated)", err)
		}
		if err := waitShutdown(t, "B", b); !errors.Is(err, ErrNotStarted) || errors.Is(err, ErrDrainTimeout) {
			t.Errorf("second Shutdown B = %v; want an error wrapping ErrNotStarted and not ErrDrainTimeout", err)
		}
		if err := waitServeErr(t, serveErr); err != nil {
			t.Fatalf("Serve = %v; want nil", err)
		}
	})
}
