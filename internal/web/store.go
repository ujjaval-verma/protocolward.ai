// SPDX-License-Identifier: Apache-2.0

// Package web hosts the read-only dashboard surface for `ward serve`.
//
// v0.1 exposes two routes:
//   - GET /        — server-rendered HTML dashboard (recent decisions table + uptime), reading from Store.SnapshotAll
//   - GET /healthz — JSON health probe (last decision summary + uptime), reading from Store.Snapshot
//
// The HTTP server binds 127.0.0.1 only; that loopback constraint is the
// load-bearing assumption that keeps DNS-decision data (qnames in both
// `last_decision.qname` and the HTML table) from being "flow data leaving
// the device" (invariant 4 corollary). The reasoning is count-agnostic:
// serving 25 qnames over the HTML route is covered by the same loopback
// reasoning as the single qname served by /healthz. A future non-loopback
// `dashboard.listen` config option requires a separate invariant 4
// re-review.
//
// # Decoy/last-decision interaction
//
// A query for a decoy hostname appears in `last_decision.qname` and in the
// HTML decisions table like any other decision. This is NOT a leak of the
// decoy list itself (invariant 6 — "decoys do not leak through config
// EXPORTS"): the surface reports what was queried, not what is configured.
// Configured-but-never-queried decoys cannot appear here because Record is
// invoked only on processed queries, never at config load. An attacker who
// sees their own tripwire query reflected back already knows they
// triggered it. This reasoning is load-bearing on the loopback bind.
//
// # Snapshot vs SnapshotAll ordering
//
// Record writes to the atomic last-pointer BEFORE taking the ring mutex,
// so a concurrent Snapshot() can return a Decision that is not yet visible
// to SnapshotAll(). This is intentional: it keeps /healthz off the hot
// mutex path. Operator-visible consequence: a /healthz JSON probe may
// show a qname that has not yet rendered into the next HTML refresh. The
// gap closes within microseconds. A future combined-status endpoint that
// requires the two reads to be consistent will need re-design.
package web

import (
	"sync"
	"sync/atomic"
	"time"
)

// ringCap bounds the dashboard's "recent decisions" table. 25 is enough to
// be useful on a quiet LAN and short enough that the table renders fast on
// a Raspberry Pi 5. Not configurable in v0.1; revisit if the rig run shows
// the table saturating (all 25 entries replaced within a 5s refresh
// window) under normal home-network load.
const ringCap = 25

// Decision is the immutable snapshot stored by Record. Action is set by
// internal/policy and constrained to "block" | "allow" | "forward" |
// "decoy". Values outside this set produce a no-op CSS class in the HTML
// template and are not escaped against CSS injection by html/template's
// attribute-context auto-escaping, so callers must enforce the constraint.
type Decision struct {
	Qname        string
	Action       string
	MatchedLabel string
	At           time.Time
}

// Store is a thread-safe holder for dashboard state: the most recent
// Decision (atomic, lock-free read for /healthz JSON) and a fixed-cap ring
// buffer of recent Decisions (mutex-protected, used by the HTML
// dashboard). Construct via NewStore.
type Store struct {
	startedAt time.Time
	last      atomic.Pointer[Decision]

	mu   sync.Mutex
	ring [ringCap]Decision
	head int  // index of NEXT write
	full bool // true once head has wrapped at least once
}

// NewStore returns a Store whose StartedAt is `time.Now()` at call time,
// whose last-decision pointer is nil, and whose ring buffer is empty.
func NewStore() *Store {
	return &Store{startedAt: time.Now()}
}

// Record stores the supplied fields as the new last-decision AND appends a
// copy into the ring buffer. The /healthz fast read uses the atomic
// pointer; the dashboard table uses the ring. See package doc for the
// deliberate Snapshot/SnapshotAll ordering window.
func (s *Store) Record(qname, action, matched string) {
	d := Decision{
		Qname:        qname,
		Action:       action,
		MatchedLabel: matched,
		At:           time.Now(),
	}
	dp := d
	s.last.Store(&dp)

	s.mu.Lock()
	s.ring[s.head] = d
	s.head = (s.head + 1) % ringCap
	if s.head == 0 {
		s.full = true
	}
	s.mu.Unlock()
}

// Snapshot returns the current most-recent Decision (ok=true) or
// zero/false when no query has been recorded yet. Lock-free.
func (s *Store) Snapshot() (Decision, bool) {
	d := s.last.Load()
	if d == nil {
		return Decision{}, false
	}
	return *d, true
}

// SnapshotAll returns a copy of the ring buffer in newest-first order.
// Returns nil when no Decisions have been recorded. Used by the dashboard
// HTML handler.
func (s *Store) SnapshotAll() []Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.head
	if s.full {
		n = ringCap
	}
	if n == 0 {
		return nil
	}
	out := make([]Decision, n)
	for i := 0; i < n; i++ {
		idx := (s.head - 1 - i + ringCap) % ringCap
		out[i] = s.ring[idx]
	}
	return out
}

// StartedAt returns the construction time. Used by the handler to compute
// uptime_seconds.
func (s *Store) StartedAt() time.Time { return s.startedAt }
