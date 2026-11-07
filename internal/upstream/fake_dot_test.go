// SPDX-License-Identifier: Apache-2.0

package upstream_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// FakeDoTOptions controls fake server behavior per connection.
type FakeDoTOptions struct {
	Rcode                  int           // DNS response code (dns.RcodeSuccess etc.)
	HangUntil              chan struct{} // if non-nil, block each response until closed
	CloseOnHandshake       bool          // drop TCP conn immediately after TLS accept
	WrongCert              bool          // serve cert for "wrong-name.test" instead of "fake-dot.test"
	CloseConnAfterResponse bool          // close the TCP connection after sending the first response

	// Latency is slept before writing each reply, per query and serially on
	// each connection: it models the round trip a non-pipelining client sees,
	// so N connections give N replies per Latency. The handshake is not delayed.
	Latency time.Duration
	// IdleClose, when non-zero, replaces the 3 s per-read deadline: the server
	// closes a connection that has been idle this long (a full close:
	// close_notify then FIN, which leaves the client socket half-closed).
	IdleClose time.Duration
	// IdleCloseAfter, when non-nil, arms IdleClose only once it is closed:
	// until then every read has the 3 s deadline. On arming, a connection
	// that is waiting for a query gets the IdleClose deadline from then on.
	IdleCloseAfter <-chan struct{}
	// ResetOnClose makes every server-side close a bare RST: SO_LINGER is set
	// to 0 and the TCP connection is closed directly, with no close_notify.
	ResetOnClose bool
	// CloseWithoutReply reads and records each query, then closes the
	// connection without replying.
	CloseWithoutReply bool
}

// FakeDoTServer is a minimal in-process DoT (DNS-over-TLS) server for tests.
//
// It records how each client close arrived: graceful when the client sent a
// TLS record (its close_notify) after its last query and before EOF, abrupt
// when the TCP connection ended with no such record. A Go client sends
// nothing else after its last query (session tickets flow server to client),
// and crypto/tls returns io.EOF for both kinds, so the raw byte count decides.
// The classification assumes a gap between the last query and the close: a
// close_notify read in the same raw read as the last query frame would count
// before the post-frame baseline and be classed abrupt. A test that queries
// and closes back to back must not assert these counters. A failed
// handshake, a read deadline, a read error other than EOF or a server-side
// close counts as neither.
type FakeDoTServer struct {
	Addr     string
	TLSConf  *tls.Config // wire this into upstream.Config.TLSConfig to verify correctly
	mu       sync.Mutex
	queries  []*dns.Msg
	opts     FakeDoTOptions
	ln       net.Listener
	tlsConf  *tls.Config // the server's TLS config
	conns    int         // connections accepted, counted at Accept (guarded by mu)
	open     int         // connections whose handler is still running (guarded by mu)
	maxOpen  int         // peak of open (guarded by mu)
	graceful int         // client closes with a close_notify (guarded by mu)
	abrupt   int         // client closes without one (guarded by mu)
}

// countingConn counts the raw bytes read from the TCP connection under TLS.
type countingConn struct {
	net.Conn
	n atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// bytesRead returns the raw bytes read so far.
func (c *countingConn) bytesRead() int64 { return c.n.Load() }

// tcpConn returns the underlying *net.TCPConn, or nil if there is none.
func (c *countingConn) tcpConn() *net.TCPConn {
	tcp, _ := c.Conn.(*net.TCPConn)
	return tcp
}

// newFakeDoT starts a fake DoT server on a random loopback port and registers
// cleanup with t. Returns the server; inspect .Addr and .TLSConf.
func newFakeDoT(t testing.TB, opts FakeDoTOptions) *FakeDoTServer {
	t.Helper()

	serverName := "fake-dot.test"
	if opts.WrongCert {
		serverName = "wrong-name.test"
	}

	tlsCert, pool := generateSelfSignedCert(t, serverName)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	// Client TLS config trusts this server's self-signed cert.
	// ServerName is set to the cert's name so tests can selectively override it to
	// trigger SNI mismatches.
	clientTLS := &tls.Config{
		RootCAs:    pool,
		ServerName: serverName, // may be "wrong-name.test" for mismatch tests
		MinVersion: tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake DoT: listen: %v", err)
	}

	s := &FakeDoTServer{
		Addr:    ln.Addr().String(),
		TLSConf: clientTLS,
		opts:    opts,
		ln:      ln,
		tlsConf: serverTLS,
	}

	t.Cleanup(func() { ln.Close() })
	go s.serve()

	return s
}

// Queries returns a snapshot of DNS messages received by the server so far.
func (s *FakeDoTServer) Queries() []*dns.Msg {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*dns.Msg, len(s.queries))
	copy(out, s.queries)
	return out
}

// Conns returns the number of connections accepted so far, counted at Accept,
// before the TLS handshake.
func (s *FakeDoTServer) Conns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

// Open returns the number of connections the server still holds open. It
// lags client-side closes until the server's read sees the EOF.
func (s *FakeDoTServer) Open() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open
}

// MaxOpen returns the peak of Open. It is a valid bound only in tests where
// the client discards no connection, because Open lags client-side closes.
func (s *FakeDoTServer) MaxOpen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxOpen
}

// GracefulCloses returns the number of client closes that sent a
// close_notify after the last query.
func (s *FakeDoTServer) GracefulCloses() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.graceful
}

// AbruptCloses returns the number of client closes that sent no TLS record
// after the last query: a bare TCP close.
func (s *FakeDoTServer) AbruptCloses() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.abrupt
}

func (s *FakeDoTServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns++
		s.open++
		if s.open > s.maxOpen {
			s.maxOpen = s.open
		}
		s.mu.Unlock()
		raw := &countingConn{Conn: conn}
		go s.handleConn(tls.Server(raw, s.tlsConf), raw)
	}
}

// closeConn closes conn the way the options ask: a TLS close (close_notify
// then FIN), or with ResetOnClose a bare RST on the TCP connection. It panics
// rather than fall back to a FIN when ResetOnClose cannot reach the TCP
// connection.
func (s *FakeDoTServer) closeConn(conn *tls.Conn, raw *countingConn) {
	if s.opts.ResetOnClose {
		tcp := raw.tcpConn()
		if tcp == nil {
			panic("fake DoT: ResetOnClose needs a *net.TCPConn under TLS")
		}
		_ = tcp.SetLinger(0)
		_ = tcp.Close()
		return
	}
	_ = conn.Close()
}

// recordClientClose classifies a client close seen as io.EOF on a frame's
// length prefix: graceful if raw bytes arrived since baseline, else abrupt.
func (s *FakeDoTServer) recordClientClose(raw *countingConn, baseline int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if raw.bytesRead() > baseline {
		s.graceful++
	} else {
		s.abrupt++
	}
}

func (s *FakeDoTServer) handleConn(conn *tls.Conn, raw *countingConn) {
	defer func() {
		s.closeConn(conn, raw)
		s.mu.Lock()
		s.open--
		s.mu.Unlock()
	}()
	if s.opts.CloseOnHandshake {
		return
	}
	hsCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	err := conn.HandshakeContext(hsCtx)
	cancel()
	if err != nil {
		return
	}
	// Raw bytes read up to the end of the handshake, then of each complete
	// query frame.
	baseline := raw.bytesRead()
	// dlMu orders the loop's deadline against the arming one, so a read
	// that started before IdleCloseAfter closed still gets IdleClose.
	var dlMu sync.Mutex
	armed := func() bool {
		if s.opts.IdleCloseAfter == nil {
			return true
		}
		select {
		case <-s.opts.IdleCloseAfter:
			return true
		default:
			return false
		}
	}
	if s.opts.IdleClose > 0 && s.opts.IdleCloseAfter != nil {
		handlerDone := make(chan struct{})
		defer close(handlerDone)
		go func() {
			select {
			case <-s.opts.IdleCloseAfter:
				dlMu.Lock()
				_ = conn.SetReadDeadline(time.Now().Add(s.opts.IdleClose))
				dlMu.Unlock()
			case <-handlerDone:
			}
		}()
	}
	for {
		dlMu.Lock()
		idle := 3 * time.Second
		if s.opts.IdleClose > 0 && armed() {
			idle = s.opts.IdleClose
		}
		err := conn.SetReadDeadline(time.Now().Add(idle))
		dlMu.Unlock()
		if err != nil {
			return
		}
		// Read 2-byte length prefix.
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			if errors.Is(err, io.EOF) {
				s.recordClientClose(raw, baseline)
			}
			return
		}
		msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		msgBuf := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msgBuf); err != nil {
			return
		}
		baseline = raw.bytesRead()

		msg := new(dns.Msg)
		if err := msg.Unpack(msgBuf); err != nil {
			return
		}

		s.mu.Lock()
		s.queries = append(s.queries, msg.Copy())
		s.mu.Unlock()

		if s.opts.HangUntil != nil {
			<-s.opts.HangUntil
			return
		}
		if s.opts.CloseWithoutReply {
			return
		}
		if s.opts.Latency > 0 {
			time.Sleep(s.opts.Latency)
		}

		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Rcode = s.opts.Rcode
		out, err := resp.Pack()
		if err != nil {
			return
		}
		// Write 2-byte length prefix + message.
		prefix := []byte{byte(len(out) >> 8), byte(len(out))}
		if _, err := conn.Write(append(prefix, out...)); err != nil {
			return
		}

		if s.opts.CloseConnAfterResponse {
			return // server-side close after first response
		}
	}
}

// generateSelfSignedCert creates a self-signed ECDSA cert for serverName.
// Returns the tls.Certificate and a CertPool that trusts it.
func generateSelfSignedCert(t testing.TB, serverName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCert: gen key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("generateSelfSignedCert: create cert: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("generateSelfSignedCert: parse cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(x509Cert)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("generateSelfSignedCert: marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("generateSelfSignedCert: X509KeyPair: %v", err)
	}

	return tlsCert, pool
}
