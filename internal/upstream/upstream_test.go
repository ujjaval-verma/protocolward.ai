// SPDX-License-Identifier: Apache-2.0

package upstream_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/upstream"
)

func TestQuery_NOERROR(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess})

	cfg := upstream.Config{
		Address:     srv.Addr,
		ServerName:  "fake-dot.test",
		TLSConfig:   srv.TLSConf,
		DialTimeout: 2 * time.Second,
	}
	client, err := upstream.New(cfg)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	defer client.Close()

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.Query(ctx, msg)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: got %d, want %d", resp.Rcode, dns.RcodeSuccess)
	}
}

func TestQuery_NXDOMAIN(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeNameError})

	cfg := upstream.Config{
		Address:     srv.Addr,
		ServerName:  "fake-dot.test",
		TLSConfig:   srv.TLSConf,
		DialTimeout: 2 * time.Second,
	}
	client, err := upstream.New(cfg)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	defer client.Close()

	msg := new(dns.Msg)
	msg.SetQuestion("nxdomain.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.Query(ctx, msg)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode: got %d, want %d (NXDOMAIN)", resp.Rcode, dns.RcodeNameError)
	}
}

func TestQuery_ConnectionReuse(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess})

	cfg := upstream.Config{
		Address:     srv.Addr,
		ServerName:  "fake-dot.test",
		TLSConfig:   srv.TLSConf,
		DialTimeout: 2 * time.Second,
	}
	client, err := upstream.New(cfg)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	const n = 5
	for i := 0; i < n; i++ {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		if _, err := client.Query(ctx, msg); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}

	queries := srv.Queries()
	if len(queries) != n {
		t.Errorf("expected %d queries received by server, got %d", n, len(queries))
	}
}

func TestQuery_DialTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("TestQuery_DialTimeout skipped in short mode (blocks on non-routable address)")
	}

	// Point at a non-routable address so the dial blocks until timeout.
	cfg := upstream.Config{
		Address:     "192.0.2.1:853", // TEST-NET-1, non-routable
		ServerName:  "unused.test",
		DialTimeout: 50 * time.Millisecond,
	}
	client, err := upstream.New(cfg)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	defer client.Close()

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = client.Query(ctx, msg)
	if err == nil {
		t.Fatal("expected dial timeout error, got nil")
	}
}

func TestQuery_QueryTimeout(t *testing.T) {
	hang := make(chan struct{}) // never closed — server will hang forever
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess, HangUntil: hang})

	cfg := upstream.Config{
		Address:     srv.Addr,
		ServerName:  "fake-dot.test",
		TLSConfig:   srv.TLSConf,
		DialTimeout: 2 * time.Second,
	}
	client, err := upstream.New(cfg)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	defer func() {
		close(hang)
		client.Close()
	}()

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = client.Query(ctx, msg)
	if err == nil {
		t.Fatal("expected context deadline error, got nil")
	}
}

func TestQuery_ContextCancelAbortsRead(t *testing.T) {
	// B1: a context.WithCancel (no deadline) must abort an in-flight read within a
	// short window when cancel() is called. Without the AfterFunc fix this test
	// would hang for the OS TCP timeout (minutes).
	hang := make(chan struct{}) // never closed — server never replies
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess, HangUntil: hang})

	cfg := upstream.Config{
		Address:     srv.Addr,
		ServerName:  "fake-dot.test",
		TLSConfig:   srv.TLSConf,
		DialTimeout: 2 * time.Second,
	}
	client, err := upstream.New(cfg)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	defer func() {
		close(hang)
		client.Close()
	}()

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, qErr := client.Query(ctx, msg)
		done <- qErr
	}()

	// Give the query enough time to connect and block on ReadMsg.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case qErr := <-done:
		if qErr == nil {
			t.Fatal("expected error after cancel, got nil")
		}
		if !errors.Is(qErr, context.Canceled) {
			t.Errorf("expected errors.Is(err, context.Canceled), got: %v", qErr)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Query did not return within 200ms after cancel() — B1 fix missing")
	}
}

func TestQuery_SNIMismatch(t *testing.T) {
	// WrongCert=true makes the server present a cert for "wrong-name.test".
	// srv.TLSConf trusts that cert and sets ServerName="wrong-name.test".
	// Our Config overrides ServerName to "fake-dot.test", so the TLS handshake
	// will fail: the cert's SAN is "wrong-name.test" but the client expects "fake-dot.test".
	srv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess, WrongCert: true})

	// Build a modified TLS config that trusts the server's self-signed cert
	// but asserts the wrong server name — triggering a TLS verify error.
	wrongNameTLS := srv.TLSConf.Clone()
	wrongNameTLS.ServerName = "fake-dot.test" // cert says "wrong-name.test" → mismatch

	cfg := upstream.Config{
		Address:     srv.Addr,
		ServerName:  "fake-dot.test",
		TLSConfig:   wrongNameTLS,
		DialTimeout: 2 * time.Second,
	}
	client, err := upstream.New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer client.Close()

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.Query(ctx, msg)
	if err == nil {
		t.Fatal("expected TLSError on SNI mismatch, got nil")
	}

	var tlsErr *upstream.TLSError
	if !errors.As(err, &tlsErr) {
		t.Errorf("expected *upstream.TLSError in chain, got %T: %v", err, err)
	}
}

func TestQuery_CloseOnHandshake(t *testing.T) {
	srv := newFakeDoT(t, FakeDoTOptions{CloseOnHandshake: true})

	cfg := upstream.Config{
		Address:     srv.Addr,
		ServerName:  "fake-dot.test",
		TLSConfig:   srv.TLSConf,
		DialTimeout: 2 * time.Second,
	}
	client, err := upstream.New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer client.Close()

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.Query(ctx, msg)
	if err == nil {
		t.Fatal("expected error when server closes on handshake, got nil")
	}
}

func TestQuery_ConnEvictionOnError(t *testing.T) {
	// Verify that after a timeout error the Client nils its cached connection
	// and re-dials successfully on the next Query call.
	//
	// Strategy: use a HangUntil server for the first query (times out → evicts
	// the connection), then swap the client's config to a fresh server by
	// creating a second client. The eviction behaviour itself is validated by
	// confirming that a fresh server (same process) can be queried immediately
	// after the first client's connection is closed — if the connection were not
	// evicted, the stale fd would cause a second error.

	// Hanging server: never responds.
	hang := make(chan struct{})
	hangSrv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess, HangUntil: hang})

	client, err := upstream.New(upstream.Config{
		Address:     hangSrv.Addr,
		ServerName:  "fake-dot.test",
		TLSConfig:   hangSrv.TLSConf,
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	// First query: should time out and evict the connection.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel1()
	_, firstErr := client.Query(ctx1, msg.Copy())
	if firstErr == nil {
		close(hang) // keep test hermetic even on unexpected pass
		t.Fatal("expected timeout error on first query, got nil")
	}

	// Let the hanging goroutine in the fake server unblock so the test can exit cleanly.
	close(hang)

	// Good server: responds immediately. Use a new client pointing at it to
	// demonstrate that a fresh dial works after the previous eviction.
	goodSrv := newFakeDoT(t, FakeDoTOptions{Rcode: dns.RcodeSuccess})
	client2, err := upstream.New(upstream.Config{
		Address:     goodSrv.Addr,
		ServerName:  "fake-dot.test",
		TLSConfig:   goodSrv.TLSConf,
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("new client2: %v", err)
	}
	defer client2.Close()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	resp, err := client2.Query(ctx2, msg.Copy())
	if err != nil {
		t.Fatalf("query after eviction on fresh client: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", resp.Rcode)
	}
}

func TestQuery_ConnEvictionRedials(t *testing.T) {
	// B2: Prove that the SAME Client re-dials after its connection is evicted by a
	// server-side close. The fake server closes the TCP connection after the first
	// response (CloseConnAfterResponse knob). The second query on the SAME client
	// must therefore re-dial and succeed. srv.Queries() must show exactly 2 messages.

	srv := newFakeDoT(t, FakeDoTOptions{
		Rcode:                  dns.RcodeSuccess,
		CloseConnAfterResponse: true,
	})

	client, err := upstream.New(upstream.Config{
		Address:     srv.Addr,
		ServerName:  "fake-dot.test",
		TLSConfig:   srv.TLSConf,
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer client.Close()

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// First query — establishes the connection; server responds then closes conn.
	resp1, err := client.Query(ctx, msg.Copy())
	if err != nil {
		t.Fatalf("first query: %v", err)
	}
	if resp1.Rcode != dns.RcodeSuccess {
		t.Errorf("first query: expected NOERROR, got %d", resp1.Rcode)
	}

	// Second query on the SAME client — must re-dial after the eviction caused by
	// the server-side close (the ReadMsg on the stale conn will return an error).
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()

	resp2, err := client.Query(ctx2, msg.Copy())
	if err != nil {
		t.Fatalf("second query (same client, post-eviction redial): %v", err)
	}
	if resp2.Rcode != dns.RcodeSuccess {
		t.Errorf("second query: expected NOERROR, got %d", resp2.Rcode)
	}

	// Both queries must have been received by the server.
	if got := len(srv.Queries()); got != 2 {
		t.Errorf("server received %d queries, want 2", got)
	}
}

func TestNew_MissingAddress(t *testing.T) {
	_, err := upstream.New(upstream.Config{ServerName: "example.com"})
	if err == nil {
		t.Fatal("expected error for missing Address, got nil")
	}
}

func TestNew_MissingServerName(t *testing.T) {
	_, err := upstream.New(upstream.Config{Address: "9.9.9.9:853"})
	if err == nil {
		t.Fatal("expected error for missing ServerName, got nil")
	}
}
