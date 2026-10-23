// SPDX-License-Identifier: Apache-2.0

// Package upstream manages DNS-over-TLS (DoT) connections to upstream resolvers.
//
// Each Client keeps a small pool of TCP/TLS connections to one upstream
// resolver, up to 16. Each connection carries one exchange at a time, so the
// pool is what lets queries run in parallel: throughput is up to 16 per round
// trip. Connections are dialled lazily, only when a query finds none idle, so
// a quiet network keeps one.
//
//   - A query first takes one of the 16 slots. The wait for a slot honours the
//     query's context: a query whose context ends while every connection is
//     busy returns at once, unsent, so a fallback resolver keeps the rest of
//     the budget. After taking a slot it re-checks, under the pool mutex, that
//     the client is not closed and its context has not ended.
//   - Idle connections form a last-in-first-out stack: a query reuses the most
//     recently used one. Connections other than the most recent one are closed
//     once they have been idle for 10 s; the most recent idle connection never
//     expires.
//   - A connection goes back on the stack only after a clean write and read; on
//     any error only that connection is closed.
//   - A failed attempt gets one retry, on a freshly dialled connection, unless
//     it is a deadline outcome: the context ended or its deadline passed, or a
//     write or read hit that deadline. A deadline outcome is never retried and
//     wraps the context error.
//   - Close closes every connection and makes in-flight, waiting and later
//     queries return ErrClosed.
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
//   - Connection eviction on error: any TLS read/write error closes the
//     connection it happened on, and no other.
package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// TLSError wraps a TLS handshake failure with a remediation hint.
// It is returned when the TLS handshake with the upstream fails. A timeout
// is reported with a connectivity remediation; other failures typically
// indicate a server_name mismatch or an untrusted certificate.
type TLSError struct {
	// Upstream is the address of the upstream resolver (host:port).
	Upstream string
	// ServerName is the SNI name that was sent during the handshake.
	ServerName string
	// Err is the underlying TLS error.
	Err error
}

func (e *TLSError) Error() string {
	if e.timedOut() {
		return fmt.Sprintf(
			"upstream %s: TLS handshake failed (server_name=%q): %v — remediation: the upstream accepted the TCP connection but did not finish the TLS handshake in time; check that it is reachable and not overloaded and that egress on TCP/853 works; the handshake is bounded by the smaller of timeouts.dial and this attempt's share of timeouts.query, so on a slow link raise whichever is smaller (timeouts.query under the defaults)",
			e.Upstream, e.ServerName, e.Err,
		)
	}
	return fmt.Sprintf(
		"upstream %s: TLS handshake failed (server_name=%q): %v — remediation: verify server_name matches the upstream cert; common cause: typo in ward.yaml or upstream certificate rotation",
		e.Upstream, e.ServerName, e.Err,
	)
}

// timedOut reports whether the handshake ran out of time rather than being
// rejected: a deadline, or a net.Error that says Timeout.
func (e *TLSError) timedOut() bool {
	if errors.Is(e.Err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(e.Err, &ne) && ne.Timeout()
}

// Unwrap implements the errors.Unwrap interface.
func (e *TLSError) Unwrap() error { return e.Err }

// ErrClosed is returned, wrapped with the upstream address, by a Query that
// runs into Close: one in flight, one waiting for a connection, or one made
// after Close.
var ErrClosed = errors.New("client closed — remediation: expected while ward is shutting down; if it appears while serving, report a bug")

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

// Client holds a pool of up to 16 DoT connections to one upstream resolver,
// one exchange in flight on each. It is safe for concurrent use. mu guards the
// idle stack, the busy set and closed; it is never held across a dial or
// network I/O, and connections are closed only after it is released.
type Client struct {
	cfg         Config
	maxConns    int           // defaultMaxConns unless a test hook sets it
	idleTimeout time.Duration // defaultIdleTimeout unless a test hook sets it
	slots       chan struct{} // cap maxConns; send = acquire, receive = release
	done        chan struct{} // closed once by Close
	afterSlot   func()        // test hook; nil in production
	afterRead   func()        // test hook between ReadMsg and stop; nil in production
	closeOnce   sync.Once

	mu     sync.Mutex
	idle   []*pconn            // LIFO; ascending lastUsed (bottom = oldest)
	busy   map[*pconn]struct{} // checked-out conns, so Close can reach them
	closed bool
}

// New creates a Client. Connections are established lazily, when a Query finds
// none idle.
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
	return newClient(cfg, defaultMaxConns, defaultIdleTimeout), nil
}

// newClient builds a Client for a validated cfg.
func newClient(cfg Config, maxConns int, idleTimeout time.Duration) *Client {
	return &Client{
		cfg:         cfg,
		maxConns:    maxConns,
		idleTimeout: idleTimeout,
		slots:       make(chan struct{}, maxConns),
		done:        make(chan struct{}),
		busy:        make(map[*pconn]struct{}),
	}
}

// Address returns the configured upstream address (host:port).
func (c *Client) Address() string { return c.cfg.Address }

// Close closes every connection, idle or in use, and makes every later or
// waiting Query return ErrClosed. It does not wait for in-flight queries:
// they see their connection fail and return ErrClosed. Safe to call more
// than once.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		close(c.done)
		all := c.idle
		c.idle = nil
		for pc := range c.busy {
			all = append(all, pc)
		}
		clear(c.busy)
		c.mu.Unlock()
		// The raw TCP connections are closed, not the TLS ones, so Close
		// never blocks on a close_notify write to an unresponsive peer.
		closeAll(all)
	})
}

// isClosed reports whether Close has run.
func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// closedErr is ErrClosed wrapped with the upstream address.
func (c *Client) closedErr() error {
	return fmt.Errorf("upstream %s: %w", c.cfg.Address, ErrClosed)
}

// Query sends msg to the upstream and returns the response.
//
// The context bounds the wait for a connection as well as the write and read.
// On any transport error the connection is closed. A failure that is not a
// deadline outcome is retried once on a freshly dialled connection, on the
// same slot: this recovers from a server-side close of an idle connection
// without requiring the caller to re-issue the query.
func (c *Client) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if err := c.precheck(ctx); err != nil {
		return nil, err
	}
	if err := c.acquireSlot(ctx); err != nil {
		return nil, err
	}
	// The slot is held in this frame for the whole query, retry included.
	// exchange releases or discards its connection before returning, so a
	// healthy connection is back on idle before the slot frees.
	defer c.releaseSlot()
	if c.afterSlot != nil {
		c.afterSlot()
	}

	for attempt := 0; ; attempt++ {
		var timedOut bool
		pc, err := c.checkout(ctx, attempt > 0)
		if err == nil {
			var resp *dns.Msg
			resp, timedOut, err = c.exchange(ctx, pc, msg)
			if err == nil {
				return resp, nil
			}
		} else {
			timedOut = isDeadlineOutcome(ctx, err)
		}
		// A query that ran into Close reports that, and is never retried.
		if c.isClosed() {
			return nil, c.closedErr()
		}
		// One retry, on a fresh dial, after any failure that is not a
		// deadline outcome.
		if attempt > 0 || timedOut {
			return nil, err
		}
	}
}
