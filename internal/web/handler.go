// SPDX-License-Identifier: Apache-2.0

package web

import (
	"embed"
	"encoding/json"
	"html/template"
	"net/http"
	"sync"
	"time"
)

//go:embed templates/index.html
var templatesFS embed.FS

var indexTmpl = template.Must(template.ParseFS(templatesFS, "templates/index.html"))

// indexView is the data shape rendered into templates/index.html.
type indexView struct {
	UptimeSeconds int64
	Decisions     []Decision
	Flags         []Flag
}

// Flag is one detector flag shown in the dashboard's Flags panel: a
// forwarded hostname whose behavioral assessment was non-benign. Flags are
// observations only — the query was answered normally (ADR-0006).
type Flag struct {
	Qname   string
	Client  string
	Score   float64
	Reasons []string
	At      time.Time
}

// flagRingCap bounds the Flags panel. 50 (twice the decisions ring) because
// flags are rarer and more important; a beaconing implant cycling DGA names
// still cannot grow memory past 50 × (qname ≤ 253 B + 3 short codes).
const flagRingCap = 50

// maxFlagReasons bounds the reason codes kept per flag, independent of what
// the recorder passes in. It deliberately duplicates the dataplane's constant
// of the same name (which caps what is sent) as defence in depth, because
// internal/web must not import internal/dataplane; change both together.
const maxFlagReasons = 3

// FlagLog holds the most recent detector flags in a fixed-capacity ring for
// the dashboard. It implements internal/dataplane.FlagRecorder. Safe for
// concurrent use. Construct via NewFlagLog. It lives beside the handler
// (not in store.go) only because of the slice's production-file cap.
type FlagLog struct {
	mu   sync.Mutex
	ring [flagRingCap]Flag
	head int  // index of NEXT write
	full bool // true once head has wrapped at least once
}

// NewFlagLog returns an empty FlagLog.
func NewFlagLog() *FlagLog { return &FlagLog{} }

// RecordFlag stores a flag stamped with time.Now(), overwriting the oldest
// once the ring is full. reasonCodes is copied and truncated to
// maxFlagReasons so the caller's slice is never retained. A nil *FlagLog is
// a no-op.
func (l *FlagLog) RecordFlag(qname, client string, score float64, reasonCodes []string) {
	if l == nil {
		return
	}
	n := min(len(reasonCodes), maxFlagReasons)
	codes := make([]string, n)
	copy(codes, reasonCodes[:n])
	f := Flag{Qname: qname, Client: client, Score: score, Reasons: codes, At: time.Now()}

	l.mu.Lock()
	l.ring[l.head] = f
	l.head = (l.head + 1) % flagRingCap
	if l.head == 0 {
		l.full = true
	}
	l.mu.Unlock()
}

// Snapshot returns the flags newest-first, or nil when there are none. A
// nil *FlagLog returns nil so HandlerWithFlags(store, nil) renders the
// empty state.
func (l *FlagLog) Snapshot() []Flag {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.head
	if l.full {
		n = flagRingCap
	}
	if n == 0 {
		return nil
	}
	out := make([]Flag, n)
	for i := 0; i < n; i++ {
		f := l.ring[(l.head-1-i+flagRingCap)%flagRingCap]
		// Deep-copy: Reasons is ring-owned; callers must not alias it.
		f.Reasons = append([]string(nil), f.Reasons...)
		out[i] = f
	}
	return out
}

// healthzResponse is the JSON shape of GET /healthz.
type healthzResponse struct {
	Status        string               `json:"status"`
	UptimeSeconds int64                `json:"uptime_seconds"`
	LastDecision  *healthzLastDecision `json:"last_decision"`
}

type healthzLastDecision struct {
	Qname        string    `json:"qname"`
	Action       string    `json:"action"`
	MatchedLabel string    `json:"matched_label,omitempty"`
	At           time.Time `json:"at"`
}

// Handler returns the dashboard handler without a flag source; the Flags
// panel renders its empty state. Equivalent to HandlerWithFlags(store, nil).
// It exists for flag-less callers and tests; production wiring
// (cmd/ward serve) uses HandlerWithFlags.
func Handler(store *Store) http.Handler { return HandlerWithFlags(store, nil) }

// HandlerWithFlags returns an http.Handler exposing the dashboard surface:
//   - GET /        — server-rendered HTML dashboard (flags panel, decisions table, uptime)
//   - GET /healthz — JSON health probe (last decision summary + uptime)
//
// Both routes read from the supplied Store; the Flags panel reads from
// flags (nil allowed). The server is expected to bind 127.0.0.1 only (see
// the Store package comment for the invariant 4 reasoning); no
// authentication is performed. All values reach HTML via html/template
// contextual escaping — qnames are attacker-influenced.
func HandlerWithFlags(store *Store, flags *FlagLog) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte("method not allowed\n"))
			return
		}
		view := indexView{
			UptimeSeconds: int64(time.Since(store.StartedAt()).Seconds()),
			Decisions:     store.SnapshotAll(),
			Flags:         flags.Snapshot(),
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = indexTmpl.Execute(w, view)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":       "method not allowed",
				"remediation": "use GET",
			})
			return
		}
		resp := healthzResponse{
			Status:        "ok",
			UptimeSeconds: int64(time.Since(store.StartedAt()).Seconds()),
		}
		if d, ok := store.Snapshot(); ok {
			resp.LastDecision = &healthzLastDecision{
				Qname:        d.Qname,
				Action:       d.Action,
				MatchedLabel: d.MatchedLabel,
				At:           d.At,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}
