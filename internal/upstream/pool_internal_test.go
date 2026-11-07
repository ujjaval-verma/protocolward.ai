// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// pastDeadlineCtx has a deadline that has passed while its Err is still nil,
// as when the context's own timer has not fired yet.
type pastDeadlineCtx struct{ context.Context }

func (pastDeadlineCtx) Deadline() (time.Time, bool) { return time.Now().Add(-time.Second), true }

func TestDeadlineOutcome(t *testing.T) {
	t.Parallel()
	live := context.Background()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	past := pastDeadlineCtx{context.Background()}

	ioTimeout := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"live ctx, I/O deadline", live, ioTimeout, true},
		{"deadline passed, Err nil", past, io.EOF, true},
		{"cancelled ctx, EOF", cancelled, io.EOF, true},
		{"live ctx, EOF", live, io.EOF, false},
		{"live ctx, ECONNRESET", live, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, false},
		{"live ctx, kernel ETIMEDOUT", live, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ETIMEDOUT}, false},
		// A dial or handshake that timed out only on DialTimeout, with ctx
		// live, is retried as on main.
		{"live ctx, dial timeout", live, &DialError{Upstream: "x", Err: ioTimeout}, false},
		{"live ctx, handshake timeout", live, &TLSError{Upstream: "x", Err: context.DeadlineExceeded}, false},
	} {
		if got := isDeadlineOutcome(tc.ctx, tc.err); got != tc.want {
			t.Errorf("%s: isDeadlineOutcome = %v, want %v", tc.name, got, tc.want)
		}
	}

	if err := deadlineError(live); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("deadlineError(live ctx) = %v, want context.DeadlineExceeded", err)
	}
	if err := deadlineError(cancelled); !errors.Is(err, context.Canceled) {
		t.Errorf("deadlineError(cancelled ctx) = %v, want context.Canceled", err)
	}
}

// selfSignedCert returns a self-signed ECDSA certificate for name and a pool
// that trusts it.
func selfSignedCert(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// stalledPipeConn returns a pconn over a net.Pipe whose TLS handshake is done
// and whose peer then never reads, so a close_notify write blocks. Cleanup
// closes both ends.
func stalledPipeConn(t *testing.T) *pconn {
	t.Helper()
	const name = "pipe.test"
	cert, pool := selfSignedCert(t, name)
	clientEnd, serverEnd := net.Pipe()

	// The server finishes the handshake, then never reads again. Session
	// tickets are off, or the TLS 1.3 server's ticket write could deadlock
	// on the synchronous pipe.
	srvDone := make(chan error, 1)
	go func() {
		srv := tls.Server(serverEnd, &tls.Config{
			Certificates:           []tls.Certificate{cert},
			MinVersion:             tls.VersionTLS12,
			SessionTicketsDisabled: true,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srvDone <- srv.HandshakeContext(ctx)
	}()
	t.Cleanup(func() {
		_ = clientEnd.Close()
		_ = serverEnd.Close()
		<-srvDone
	})

	cli := tls.Client(clientEnd, &tls.Config{RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS12})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := cli.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	select {
	case err := <-srvDone:
		srvDone <- err // for the cleanup wait
		if err != nil {
			t.Fatalf("server handshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server handshake did not finish within 2s")
	}
	return &pconn{dc: &dns.Conn{Conn: cli}, raw: clientEnd}
}

// A close_notify to a peer that has stopped reading is cut off after
// closeNotifyTimeout, not after tls's own 5 s write deadline.
func TestCloseGracefully_Bounded(t *testing.T) {
	t.Parallel()
	pc := stalledPipeConn(t)
	t0 := time.Now()
	closeGracefully([]*pconn{pc})
	if el, limit := time.Since(t0), closeNotifyTimeout+400*time.Millisecond; el > limit {
		t.Errorf("closeGracefully took %v against a peer that does not read, want <= %v", el, limit)
	}
}

// offQueryLimit is well under closeNotifyTimeout: a close that returns within
// it did not wait on the peer's close_notify.
const offQueryLimit = 50 * time.Millisecond

// A failed connection is closed raw: discard returns at once even though a
// close_notify would block on the stalled peer.
func TestDiscard_RawClose_NoWait(t *testing.T) {
	t.Parallel()
	c := newClient(Config{Address: "pipe.test:853"}, 4, time.Minute)
	pc := stalledPipeConn(t)
	c.mu.Lock()
	c.busy[pc] = struct{}{}
	c.mu.Unlock()
	t0 := time.Now()
	c.discard(pc)
	if el := time.Since(t0); el > offQueryLimit {
		t.Errorf("discard took %v against a stalled peer, want <= %v (raw close)", el, offQueryLimit)
	}
}

// A connection released after Close is closed raw, not through TLS.
func TestRelease_AfterClose_RawClose_NoWait(t *testing.T) {
	t.Parallel()
	c := newClient(Config{Address: "pipe.test:853"}, 4, time.Minute)
	pc := stalledPipeConn(t)
	// Not in busy, so Close does not reach it: release's own close is the
	// one under test.
	c.Close()
	t0 := time.Now()
	c.release(pc)
	if el := time.Since(t0); el > offQueryLimit {
		t.Errorf("release after Close took %v against a stalled peer, want <= %v (raw close)", el, offQueryLimit)
	}
}

// The expiry close runs off the query path: release returns at once even
// though closing the expired connection blocks on a stalled peer.
func TestRelease_ExpiryClose_OffQueryPath(t *testing.T) {
	t.Parallel()
	c := newClient(Config{Address: "pipe.test:853"}, 4, time.Millisecond)
	expired := stalledPipeConn(t)
	expired.lastUsed = time.Now().Add(-time.Hour)
	other := stalledPipeConn(t)
	c.mu.Lock()
	c.idle = append(c.idle, expired)
	c.busy[other] = struct{}{}
	c.mu.Unlock()

	t0 := time.Now()
	c.release(other)
	el := time.Since(t0)

	// The background close is bounded by closeNotifyTimeout; wait for it
	// (the raw conn closes) so the goroutine ends with the test.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := expired.raw.Write([]byte{0}); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expired connection was never closed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if el > offQueryLimit {
		t.Errorf("release took %v with an expired stalled connection, want <= %v (close off the query path)", el, offQueryLimit)
	}
}
