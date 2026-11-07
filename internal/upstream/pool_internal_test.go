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

// A close_notify to a peer that has stopped reading is cut off after
// closeNotifyTimeout, not after tls's own 5 s write deadline.
func TestCloseGracefully_Bounded(t *testing.T) {
	t.Parallel()
	const name = "pipe.test"
	cert, pool := selfSignedCert(t, name)
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()

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
	defer func() {
		_ = serverEnd.Close()
		<-srvDone
	}()

	cli := tls.Client(clientEnd, &tls.Config{RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS12})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := cli.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	select {
	case err := <-srvDone:
		srvDone <- err // for the deferred wait
		if err != nil {
			t.Fatalf("server handshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server handshake did not finish within 2s")
	}

	pc := &pconn{dc: &dns.Conn{Conn: cli}, raw: clientEnd}
	t0 := time.Now()
	closeGracefully([]*pconn{pc})
	if el, limit := time.Since(t0), closeNotifyTimeout+400*time.Millisecond; el > limit {
		t.Errorf("closeGracefully took %v against a peer that does not read, want <= %v", el, limit)
	}
}
