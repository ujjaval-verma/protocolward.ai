// SPDX-License-Identifier: Apache-2.0

// Package upstream manages DNS-over-TLS (DoT) connections to upstream resolvers.
//
// Each Client holds a single persistent TCP/TLS connection to one upstream
// resolver. Concurrent calls to Query are serialised through the cached
// *dns.Conn (miekg/dns handles DNS message-ID framing on the wire; however,
// because a single tls.Conn is not safe for concurrent writes from multiple
// goroutines without external synchronisation, mu is held across the
// Write+Read pair so that only one in-flight query exists at a time per
// connection. This keeps the implementation correct without depending on
// miekg's internal multiplexer behaviour.)
//
// # TLS roots
//
// System TLS roots are used, not pinned certificates. The threat model for
// this tier accepts system roots because the resolver address and server name
// are operator-supplied in ward.yaml and the TLS handshake enforces
// certificate validity + server-name matching. Cert pinning is a deferred
// hardening pass — see docs/engineering/invariants.md invariant #6 context
// and the relevant ADR when it lands.
//
// # Invariants
//
//   - No silent drops: every error path returns a typed error with a remediation
//     hint (invariant #8).
//   - Connection eviction on error: any TLS read/write error nils the cached
//     connection so the next Query call dials fresh.
package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// TLSError wraps a TLS handshake failure with a remediation hint.
// It is returned when the TLS handshake with the upstream fails, which
// typically indicates a server_name mismatch or an untrusted certificate.
type TLSError struct {
	// Upstream is the address of the upstream resolver (host:port).
	Upstream string
	// ServerName is the SNI name that was sent during the handshake.
	ServerName string
	// Err is the underlying TLS error.
	Err error
}

func (e *TLSError) Error() string {
	return fmt.Sprintf(
		"upstream %s: TLS handshake failed (server_name=%q): %v — remediation: verify server_name matches the upstream cert; common cause: typo in ward.yaml or upstream certificate rotation",
		e.Upstream, e.ServerName, e.Err,
	)
}

// Unwrap implements the errors.Unwrap interface.
func (e *TLSError) Unwrap() error { return e.Err }

// DialError wraps a TCP dial failure with a remediation hint.
type DialError struct {
	// Upstream is the address of the upstream resolver (host:port).
	Upstream string
	// Err is the underlying dial error.
	Err error
}

func (e *DialError) Error() string {
	return fmt.Sprintf(
		"upstream %s: dial failed: %v — remediation: check network egress on TCP/853; verify the upstream address in ward.yaml",
		e.Upstream, e.Err,
	)
}

// Unwrap implements the errors.Unwrap interface.
func (e *DialError) Unwrap() error { return e.Err }

// Config parameterises a single upstream DoT client.
type Config struct {
	// Address is host:port of the DoT resolver (e.g. "9.9.9.9:853").
	Address string
	// ServerName is the expected TLS SNI / certificate server name
	// (e.g. "dns.quad9.net"). Must not be empty.
	ServerName string
	// TLSConfig overrides the TLS client configuration. When nil, system roots
	// are used and ServerName is applied from the Config.ServerName field.
	TLSConfig *tls.Config
	// DialTimeout bounds the TCP connect + TLS handshake. Defaults to 3s.
	DialTimeout time.Duration
}

// Client holds a single persistent DoT connection to one upstream resolver.
// It is safe for concurrent use; however, only one query can be in-flight at
// a time on the shared connection (mu is held across write+read).
type Client struct {
	cfg  Config
	mu   sync.Mutex
	conn *dns.Conn // guarded by mu; nil = not yet connected or was evicted
}

// New creates a Client. The TLS connection is established lazily on the first
// Query call.
func New(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("upstream.New: Address must not be empty — remediation: set address in ward.yaml upstreams entry")
	}
	if cfg.ServerName == "" {
		return nil, fmt.Errorf("upstream.New: ServerName must not be empty — remediation: set server_name in ward.yaml upstreams entry")
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 3 * time.Second
	}
	return &Client{cfg: cfg}, nil
}

// Address returns the configured upstream address (host:port).
func (c *Client) Address() string { return c.cfg.Address }

// Close tears down the cached connection. Safe to call multiple times.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeConnLocked()
}

// Query sends msg to the upstream and returns the response.
//
// The context deadline and cancellation are both applied to the query
// (write + read). On any transport error the cached connection is evicted.
// A single transparent retry is attempted on write/read failure when the
// context is still live — this recovers from server-side connection closes
// without requiring the caller to re-issue the query.
func (c *Client) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.queryOnce(ctx, msg)
	if err == nil {
		return resp, nil
	}
	// If the context is already done, don't retry — the caller cancelled.
	if ctx.Err() != nil {
		return nil, err
	}
	// Transparent single retry: the cached conn may have been evicted above;
	// ensureConnLocked will re-dial.
	return c.queryOnce(ctx, msg)
}

// queryOnce performs one attempt at sending msg and reading the response.
// Must be called with mu held.
func (c *Client) queryOnce(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	conn, err := c.ensureConnLocked(ctx)
	if err != nil {
		return nil, err
	}

	// Apply context deadline via SetDeadline for the deadline case.
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			c.closeConnLocked()
			return nil, fmt.Errorf("upstream %s: set deadline: %w — remediation: check system clock; this is unexpected", c.cfg.Address, err)
		}
	}

	// Register an AfterFunc that fires on context cancellation (cancel() or
	// deadline expiry) and unblocks any in-progress ReadMsg/WriteMsg by setting
	// an immediate read deadline. context.AfterFunc spawns a goroutine on
	// cancellation — this is intentional and expected; the goroutine is
	// short-lived (sets a deadline and exits) and promptly unblocks the
	// in-flight ReadMsg without requiring a select loop in the hot path.
	stopCancel := context.AfterFunc(ctx, func() {
		conn.SetReadDeadline(time.Now()) //nolint:errcheck // best-effort unblock
	})
	defer stopCancel()

	if err := conn.WriteMsg(msg); err != nil {
		c.closeConnLocked()
		return nil, fmt.Errorf("upstream %s: write: %w — remediation: upstream may have closed the connection; it will be re-dialed on next query", c.cfg.Address, err)
	}

	resp, err := conn.ReadMsg()
	if err != nil {
		c.closeConnLocked()
		// Prefer ctx error so callers can errors.Is(err, context.Canceled).
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("upstream %s: read: %w", c.cfg.Address, ctxErr)
		}
		return nil, fmt.Errorf("upstream %s: read: %w — remediation: upstream may be unreachable or overloaded; check network egress on TCP/853", c.cfg.Address, err)
	}

	return resp, nil
}

// ensureConnLocked dials and performs a TLS handshake if no cached connection
// exists. Must be called with mu held.
func (c *Client) ensureConnLocked(ctx context.Context) (*dns.Conn, error) {
	if c.conn != nil {
		return c.conn, nil
	}

	// Build the TLS config. If the caller supplied one, use it as-is (useful
	// for tests with self-signed certs). Otherwise, build from Config fields so
	// the ServerName drives SNI + cert verification.
	tlsCfg := c.cfg.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			ServerName: c.cfg.ServerName,
			MinVersion: tls.VersionTLS12,
			// System roots — see package-level comment on the pinning rationale.
		}
	}

	dialCtx, cancel := context.WithTimeout(ctx, c.cfg.DialTimeout)
	defer cancel()

	rawConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", c.cfg.Address)
	if err != nil {
		return nil, &DialError{Upstream: c.cfg.Address, Err: err}
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		rawConn.Close()
		return nil, &TLSError{Upstream: c.cfg.Address, ServerName: c.cfg.ServerName, Err: err}
	}

	c.conn = &dns.Conn{Conn: tlsConn}
	return c.conn, nil
}

// closeConnLocked closes and nils the cached connection. Must be called with mu held.
func (c *Client) closeConnLocked() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}
