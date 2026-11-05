// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
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
