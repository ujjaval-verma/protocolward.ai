// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/miekg/dns"
)

const (
	// defaultMaxConns bounds the connections, and so the exchanges in flight,
	// per upstream. Each connection carries one exchange at a time, so
	// throughput is defaultMaxConns per round trip.
	defaultMaxConns = 16
	// defaultIdleTimeout is how long an idle connection other than the most
	// recently used one is kept before the next checkout or release closes it.
	defaultIdleTimeout = 10 * time.Second
)

// pconn is one pooled DoT connection.
type pconn struct {
	dc       *dns.Conn // framing over the *tls.Conn
	raw      net.Conn  // the TCP connection under TLS; closed directly
	lastUsed time.Time // set when the connection is pushed onto idle
}

// closeAll closes the raw TCP connection of each pconn. Never call it with
// c.mu held.
func closeAll(pcs []*pconn) {
	for _, pc := range pcs {
		_ = pc.raw.Close()
	}
}

// acquireSlot waits for the right to run one exchange. It honours ctx: a
// query whose ctx ends while every connection is busy returns at once,
// without having been sent. A free slot is taken first, before the blocking
// select, so it never loses the select's random pick to an ended ctx and the
// wait error never claims every connection is in use when one was free.
func (c *Client) acquireSlot(ctx context.Context) error {
	select {
	case c.slots <- struct{}{}:
		return nil
	default:
	}
	select {
	case c.slots <- struct{}{}:
		return nil
	case <-c.done:
		return c.closedErr()
	case <-ctx.Done():
		return fmt.Errorf("upstream %s: no free connection before the query's context ended (all %d in use): %w — remediation: the upstream is answering slower than queries arrive; check latency to this upstream, add another entry under upstreams in ward.yaml, or raise timeouts.query on a slow link",
			c.cfg.Address, c.maxConns, ctx.Err())
	}
}

// releaseSlot gives back the slot taken by acquireSlot.
func (c *Client) releaseSlot() {
	<-c.slots
	if c.afterFree != nil {
		c.afterFree()
	}
}

// recheckLocked is the check made before the slot wait and again after it,
// before any reuse or dial: a closed client returns ErrClosed, and an ended
// ctx the plain context error. select picks a ready case at random, so a
// query can win a slot even though Close ran or its ctx ended; this check
// keeps it from reusing or dialling a connection. Must be called with c.mu
// held.
func (c *Client) recheckLocked(ctx context.Context) error {
	if c.closed {
		return c.closedErr()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("upstream %s: %w", c.cfg.Address, err)
	}
	return nil
}

// precheck runs recheckLocked under c.mu.
func (c *Client) precheck(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recheckLocked(ctx)
}

// checkout returns a connection for one exchange, marked busy. The caller
// holds a slot. It re-checks ctx under c.mu first, then pops the most
// recently used idle connection; when there is none, or fresh is set (the
// retry), it dials a new one.
func (c *Client) checkout(ctx context.Context, fresh bool) (*pconn, error) {
	c.mu.Lock()
	if err := c.recheckLocked(ctx); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	expired := c.sweepLocked(time.Now())
	if !fresh {
		if n := len(c.idle); n > 0 {
			pc := c.idle[n-1]
			c.idle[n-1] = nil
			c.idle = c.idle[:n-1]
			c.busy[pc] = struct{}{}
			c.mu.Unlock()
			closeAll(expired)
			return pc, nil
		}
	}
	c.mu.Unlock()
	closeAll(expired)

	pc, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		// Close ran during the dial: it cannot have reached this
		// connection, so close it here.
		c.mu.Unlock()
		_ = pc.raw.Close()
		return nil, c.closedErr()
	}
	c.busy[pc] = struct{}{}
	c.mu.Unlock()
	return pc, nil
}

// release returns a connection that finished a clean exchange to the top of
// the idle stack. It must run before the slot is released, or the next
// waiter finds idle empty and dials one connection too many.
func (c *Client) release(pc *pconn) {
	c.mu.Lock()
	delete(c.busy, pc)
	if c.closed {
		c.mu.Unlock()
		_ = pc.raw.Close()
		return
	}
	now := time.Now()
	pc.lastUsed = now
	c.idle = append(c.idle, pc)
	expired := c.sweepLocked(now)
	c.mu.Unlock()
	closeAll(expired)
}

// sweepLocked removes and returns the idle connections that have expired,
// oldest first, for the caller to close after unlocking. The top of the
// stack, the most recently used connection, never expires: a quiet network
// keeps one warm connection. The stack is in ascending lastUsed order, so the
// sweep stops at the first connection that is still fresh. Must be called
// with c.mu held.
func (c *Client) sweepLocked(now time.Time) []*pconn {
	n := 0
	for n < len(c.idle)-1 && now.Sub(c.idle[n].lastUsed) > c.idleTimeout {
		n++
	}
	if n == 0 {
		return nil
	}
	expired := make([]*pconn, n)
	copy(expired, c.idle[:n])
	rest := copy(c.idle, c.idle[n:])
	clear(c.idle[rest:])
	c.idle = c.idle[:rest]
	return expired
}

// discard drops a connection after any failure. Only that connection is
// closed.
func (c *Client) discard(pc *pconn) {
	c.mu.Lock()
	delete(c.busy, pc)
	c.mu.Unlock()
	_ = pc.raw.Close()
}

// dial opens a new TCP connection and completes the TLS handshake, bounded by
// ctx and DialTimeout. It never holds c.mu.
func (c *Client) dial(ctx context.Context) (*pconn, error) {
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
		_ = rawConn.Close()
		return nil, &TLSError{Upstream: c.cfg.Address, ServerName: c.cfg.ServerName, Err: err}
	}
	return &pconn{dc: &dns.Conn{Conn: tlsConn}, raw: rawConn}, nil
}

// exchange writes msg and reads the reply on pc. On return pc has been
// released to the idle stack (a clean exchange) or discarded (anything else).
// timedOut reports a deadline outcome, which the caller never retries.
func (c *Client) exchange(ctx context.Context, pc *pconn, msg *dns.Msg) (_ *dns.Msg, timedOut bool, _ error) {
	healthy := false
	defer func() {
		if healthy {
			c.release(pc)
		} else {
			c.discard(pc)
		}
	}()

	// Always set the deadline, zero when ctx has none, so a deadline left
	// from an earlier exchange on this connection never applies to this one.
	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	if err := pc.dc.SetDeadline(deadline); err != nil {
		return nil, false, fmt.Errorf("upstream %s: set deadline: %w — remediation: check system clock; this is unexpected", c.cfg.Address, err)
	}

	// Unblock an in-progress write or read when ctx ends (cancel() or the
	// deadline). If stop reports that the callback already ran or is about
	// to, the connection may yet get a deadline of now, so it is discarded
	// even when the reply arrived.
	stop := context.AfterFunc(ctx, func() {
		pc.dc.SetDeadline(time.Now()) //nolint:errcheck // best-effort unblock
	})

	if err := pc.dc.WriteMsg(msg); err != nil {
		stop()
		if isDeadlineOutcome(ctx, err) {
			return nil, true, fmt.Errorf("upstream %s: write: %w", c.cfg.Address, deadlineError(ctx))
		}
		return nil, false, fmt.Errorf("upstream %s: write: %w — remediation: upstream may have closed the connection; it will be re-dialed on next query", c.cfg.Address, err)
	}

	resp, err := pc.dc.ReadMsg()
	if c.afterRead != nil {
		c.afterRead()
	}
	stopped := stop()
	if err != nil {
		// A deadline outcome wraps the ctx error so callers can
		// errors.Is(err, context.Canceled) or context.DeadlineExceeded.
		if isDeadlineOutcome(ctx, err) {
			return nil, true, fmt.Errorf("upstream %s: read: %w", c.cfg.Address, deadlineError(ctx))
		}
		return nil, false, fmt.Errorf("upstream %s: read: %w — remediation: upstream may be unreachable or overloaded; check network egress on TCP/853", c.cfg.Address, err)
	}
	healthy = stopped
	return resp, false, nil
}

// isDeadlineOutcome reports whether a failed attempt ran out of time, in
// which case it is never retried and closes no other connection. It holds
// when ctx has ended, when ctx's deadline has passed (its timer may not have
// fired yet), or when a write or read on the connection hit its deadline,
// which is ctx's deadline by construction. Only os.ErrDeadlineExceeded counts
// for the last: a kernel ETIMEDOUT is a transport failure. A dial or
// handshake failure is judged by ctx alone, so one that timed out only on
// DialTimeout, with ctx live, is retried as before.
func isDeadlineOutcome(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return true
	}
	if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) {
		return true
	}
	var dialErr *DialError
	var tlsErr *TLSError
	if errors.As(err, &dialErr) || errors.As(err, &tlsErr) {
		return false
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// deadlineError is the error a deadline outcome wraps: ctx.Err() once set,
// else context.DeadlineExceeded, so errors.Is(err, context.DeadlineExceeded)
// holds even before ctx's own timer fires.
func deadlineError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return context.DeadlineExceeded
}
