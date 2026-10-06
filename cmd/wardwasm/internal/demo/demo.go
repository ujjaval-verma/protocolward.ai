// SPDX-License-Identifier: Apache-2.0

// Package demo is the plain-Go core of the wardwasm browser build. It
// wires Ward's real decoy set, hostlist matchers and policy engine into
// the four calls the browser makes (Init, Assess, Decide, ExportConfig)
// and returns plain structs. cmd/wardwasm/main_js.go only converts these
// to and from JS values, so everything here is unit-tested natively.
//
// Decide is a pure decision: nothing is resolved or forwarded, and no
// network or filesystem is touched (invariant 4). Its order mirrors
// internal/dataplane.handleQuery exactly: decoy short-circuit first (an
// allowlist cannot mask a decoy), then policy.Engine.Decide (allow >
// block > forward). Only a decoy hit alerts. Input is validated first
// (normalizeName); that front gate is stricter than the dataplane's
// lowercase + trailing-dot strip, but it never changes the order.
//
// Assess is flag-only: no Decision is ever derived from it. Unlike ward
// serve, it does not skip LAN-client OS connectivity probes (S2 DD9); it
// is a faithful passthrough of pkg/detect.
//
// A Demo is not safe for concurrent use; js/wasm runs callbacks on one
// goroutine.
package demo

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"protocolward.ai/ward/internal/configexport"
	"protocolward.ai/ward/internal/decoy"
	"protocolward.ai/ward/internal/hostlist"
	"protocolward.ai/ward/internal/policy"
	"protocolward.ai/ward/pkg/detect"
	"protocolward.ai/ward/pkg/model"
)

const (
	// MaxEntriesPerList bounds each Init list so a page cannot make the
	// wasm heap balloon.
	MaxEntriesPerList = 10_000
	// MaxInputLen bounds any single Init entry. Decide/Assess input is
	// bounded more tightly by normalizeName (253).
	MaxInputLen = 1024

	maxHostnameLen = 253
	maxLabelLen    = 63
)

// Fixed values of the exported demo document. A real ward.yaml holds these
// as operator settings; the demo shows the shipped defaults.
const (
	exportListen         = "127.0.0.1:53"
	exportLogLevel       = "info"
	exportUpstreamAddr   = "9.9.9.9:853"
	exportUpstreamServer = "dns.quad9.net"
	exportDialTimeout    = "3s"
	exportQueryTimeout   = "2s"
	exportShutdownTime   = "5s"
	exportBlocklistID    = "demo-blocklist"
	exportBlocklistPath  = "blocklist.txt"
	exportAllowlistID    = "demo-allowlist"
	exportAllowlistPath  = "allowlist.txt"
)

// Decision.Action values.
const (
	ActionForward = "forward"
	ActionBlock   = "block"
)

// Decision.Source values.
const (
	SourceDecoy     = "decoy"
	SourceBlocklist = "blocklist"
	SourceAllowlist = "allowlist"
	SourceForward   = "forward"
)

var (
	// ErrInvalidHostname is returned for input that is not a hostname
	// (empty, > 253 chars, bad labels). The UI shows its text verbatim.
	ErrInvalidHostname = errors.New("not a valid hostname")
	// ErrTooManyEntries is returned when an Init list exceeds MaxEntriesPerList.
	ErrTooManyEntries = fmt.Errorf("too many entries (limit %d)", MaxEntriesPerList)
	// ErrEntryTooLong is returned when an Init entry exceeds MaxInputLen bytes.
	ErrEntryTooLong = fmt.Errorf("entry longer than %d bytes", MaxInputLen)
)

// Config is the demo configuration passed once via ward.init.
type Config struct {
	Decoys    []string
	Blocklist []string
	Allowlist []string
}

// Decision is the result of Decide, shaped like the JS surface
// {action, source, matched, alert}.
type Decision struct {
	Action  string
	Source  string
	Matched string
	Alert   bool
}

// Map returns d as a js.ValueOf-compatible object.
func (d Decision) Map() map[string]any {
	return map[string]any{"action": d.Action, "source": d.Source, "matched": d.Matched, "alert": d.Alert}
}

// Demo holds the compiled demo configuration and the detector.
type Demo struct {
	detector *detect.Lexical
	decoys   *decoy.Set
	engine   *policy.Engine
	hasBlock bool
	hasAllow bool
}

// New returns a Demo with empty lists: Decide forwards everything until
// Init is called. Assess works without Init.
func New() *Demo {
	return &Demo{detector: detect.New(), engine: policy.NewEngine(nil, nil)}
}

// Init compiles c and replaces the current configuration. Init is
// all-or-nothing: on any error the previous configuration stays in place.
func (d *Demo) Init(c Config) error {
	lists := []struct {
		name    string
		entries []string
	}{{"decoys", c.Decoys}, {"blocklist", c.Blocklist}, {"allowlist", c.Allowlist}}
	for _, l := range lists {
		if err := checkList(l.name, l.entries); err != nil {
			return err
		}
	}
	decoys, err := decoy.FromEntries(c.Decoys)
	if err != nil {
		return fmt.Errorf("init: decoys: %w", err)
	}
	block, err := hostlist.FromEntries(c.Blocklist)
	if err != nil {
		return fmt.Errorf("init: blocklist: %w", err)
	}
	allow, err := hostlist.FromEntries(c.Allowlist)
	if err != nil {
		return fmt.Errorf("init: allowlist: %w", err)
	}
	d.decoys = decoys
	d.engine = policy.NewEngine(allow, block)
	d.hasBlock = len(c.Blocklist) > 0
	d.hasAllow = len(c.Allowlist) > 0
	return nil
}

// CheckListLen reports ErrTooManyEntries when an Init list of n entries
// exceeds MaxEntriesPerList. The JS bridge calls it before copying a list
// so the message is formatted in one place.
func CheckListLen(name string, n int) error {
	if n > MaxEntriesPerList {
		return fmt.Errorf("init: %s has %d entries: %w", name, n, ErrTooManyEntries)
	}
	return nil
}

func checkList(name string, entries []string) error {
	if err := CheckListLen(name, len(entries)); err != nil {
		return err
	}
	for i, e := range entries {
		if len(e) > MaxInputLen {
			return fmt.Errorf("init: %s[%d]: %w", name, i, ErrEntryTooLong)
		}
	}
	return nil
}

// Decide returns what Ward's dataplane would do with a query for name.
// It is a pure decision; nothing is forwarded.
func (d *Demo) Decide(name string) (Decision, error) {
	q, err := normalizeName(name)
	if err != nil {
		return Decision{}, err
	}
	if d.decoys != nil {
		if _, matched, ok := d.decoys.Match(q); ok {
			return Decision{Action: ActionBlock, Source: SourceDecoy, Matched: matched, Alert: true}, nil
		}
	}
	pd := d.engine.Decide(q)
	switch pd.Action {
	case policy.ActionAllow:
		return Decision{Action: ActionForward, Source: SourceAllowlist, Matched: pd.MatchedLabel}, nil
	case policy.ActionBlock:
		return Decision{Action: ActionBlock, Source: SourceBlocklist, Matched: pd.MatchedLabel}, nil
	case policy.ActionForward:
		return Decision{Action: ActionForward, Source: SourceForward}, nil
	default:
		panic(fmt.Sprintf("demo: missing handler for policy.Action %v (invariant #2 violation)", pd.Action))
	}
}

// ErrorMessage is the user-facing text for err: invalid-hostname errors
// collapse to ErrInvalidHostname's text; everything else passes through.
func ErrorMessage(err error) string {
	if errors.Is(err, ErrInvalidHostname) {
		return ErrInvalidHostname.Error()
	}
	return err.Error()
}

// normalizeName lowercases, trims spaces and one trailing dot, then
// validates RFC 1035-ish shape (underscore allowed for SRV-style labels).
func normalizeName(raw string) (string, error) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if n == "" || len(n) > maxHostnameLen {
		return "", ErrInvalidHostname
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > maxLabelLen || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidHostname
		}
		for i := 0; i < len(label); i++ {
			switch c := label[i]; {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return "", ErrInvalidHostname
			}
		}
	}
	return n, nil
}

// ExportConfig renders the demo configuration the way `ward config export`
// would: through configexport.Marshal, whose Document type has no decoy
// field (invariant 6). Lists appear as file-backed sources because that
// is what a real ward.yaml holds; list entries never appear.
func (d *Demo) ExportConfig() (string, error) {
	doc := configexport.Document{
		Listen:    exportListen,
		LogLevel:  exportLogLevel,
		Upstreams: []configexport.Upstream{{Address: exportUpstreamAddr, ServerName: exportUpstreamServer}},
		Timeouts:  configexport.Timeouts{Dial: exportDialTimeout, Query: exportQueryTimeout, Shutdown: exportShutdownTime},
	}
	if d.hasBlock {
		doc.Blocklists = []hostlist.Source{{ID: exportBlocklistID, Path: exportBlocklistPath}}
	}
	if d.hasAllow {
		doc.Allowlists = []hostlist.Source{{ID: exportAllowlistID, Path: exportAllowlistPath}}
	}
	out, err := configexport.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("exportConfig: %w", err)
	}
	return string(out), nil
}

// Reason is one contribution to an Assessment's score.
type Reason struct {
	Code   string
	Detail string
	Weight float64
}

// Assessment is the detector's flag for one hostname, shaped like the JS
// surface {verdict, score, reasons}. Reasons is never nil.
type Assessment struct {
	Verdict string
	Score   float64
	Reasons []Reason
}

// Map returns a as a js.ValueOf-compatible object. reasons is always an
// array (never null) so the page can iterate it unconditionally.
func (a Assessment) Map() map[string]any {
	reasons := make([]any, 0, len(a.Reasons))
	for _, r := range a.Reasons {
		reasons = append(reasons, map[string]any{"code": r.Code, "detail": r.Detail, "weight": r.Weight})
	}
	return map[string]any{"verdict": a.Verdict, "score": a.Score, "reasons": reasons}
}

// Assess runs Ward's lexical detector on name. It is flag-only (ADR-0006):
// the result never feeds Decide, and a malicious verdict means "flagged",
// never "blocked". Known limit: ward serve skips LAN-client OS
// connectivity probes before assessing (dataplane connectivityProbeZones);
// Assess does not, so it shows the raw detector score for those names.
func (d *Demo) Assess(ctx context.Context, name string) (Assessment, error) {
	q, err := normalizeName(name)
	if err != nil {
		return Assessment{}, err
	}
	a, err := d.detector.Assess(ctx, model.Input{Hostname: q})
	if err != nil {
		// normalizeName is stricter than the detector's own validation, so
		// detect.ErrInvalidHostname cannot occur here; anything else is a
		// real failure.
		return Assessment{}, fmt.Errorf("assess: %w", err)
	}
	// Reuse schema's canonical wire names ("benign", ...) rather than
	// re-spelling them here.
	wire, err := a.Verdict.MarshalJSON()
	if err != nil {
		return Assessment{}, fmt.Errorf("assess: %w", err)
	}
	verdict, err := strconv.Unquote(string(wire))
	if err != nil {
		return Assessment{}, fmt.Errorf("assess: verdict %s: %w", wire, err)
	}
	out := Assessment{Verdict: verdict, Score: a.Score, Reasons: make([]Reason, 0, len(a.Reasons))}
	for _, r := range a.Reasons {
		out.Reasons = append(out.Reasons, Reason{Code: r.Code, Detail: r.Detail, Weight: r.Weight})
	}
	return out, nil
}
