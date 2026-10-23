// SPDX-License-Identifier: Apache-2.0

package upstream_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"sync"
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
	// ResetOnClose makes every server-side close a bare RST: SO_LINGER is set
	// to 0 and the TCP connection is closed directly, with no close_notify.
	ResetOnClose bool
	// CloseWithoutReply reads and records each query, then closes the
	// connection without replying.
	CloseWithoutReply bool
}

// FakeDoTServer is a minimal in-process DoT (DNS-over-TLS) server for tests.
type FakeDoTServer struct {
	Addr    string
	TLSConf *tls.Config // wire this into upstream.Config.TLSConfig to verify correctly
	mu      sync.Mutex
	queries []*dns.Msg
	opts    FakeDoTOptions
	ln      net.Listener
	conns   int // connections accepted, counted at Accept (guarded by mu)
	open    int // connections whose handler is still running (guarded by mu)
	maxOpen int // peak of open (guarded by mu)
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

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("fake DoT: listen: %v", err)
	}

	s := &FakeDoTServer{
		Addr:    ln.Addr().String(),
		TLSConf: clientTLS,
		opts:    opts,
		ln:      ln,
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
		go s.handleConn(conn)
	}
}

// closeConn closes conn the way the options ask: a TLS close (close_notify
// then FIN), or with ResetOnClose a bare RST on the TCP connection.
func (s *FakeDoTServer) closeConn(conn net.Conn) {
	if s.opts.ResetOnClose {
		if tc, ok := conn.(*tls.Conn); ok {
			if tcp, ok := tc.NetConn().(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
				_ = tcp.Close()
				return
			}
		}
	}
	_ = conn.Close()
}

func (s *FakeDoTServer) handleConn(conn net.Conn) {
	defer func() {
		s.closeConn(conn)
		s.mu.Lock()
		s.open--
		s.mu.Unlock()
	}()
	if s.opts.CloseOnHandshake {
		return
	}
	idle := 3 * time.Second
	if s.opts.IdleClose > 0 {
		idle = s.opts.IdleClose
	}
	for {
		if err := conn.SetReadDeadline(time.Now().Add(idle)); err != nil {
			return
		}
		// Read 2-byte length prefix.
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		msgBuf := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msgBuf); err != nil {
			return
		}

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
