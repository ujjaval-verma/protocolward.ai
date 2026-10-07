// SPDX-License-Identifier: Apache-2.0

// Package dataplane implements the DNS listener and query dispatcher for ward.
//
// It listens on UDP and TCP (via miekg/dns.Server), dispatches each incoming
// query to a round-robin selection of Resolvers, retries once on the next
// resolver on failure, and returns SERVFAIL if all attempts fail.
//
// # Invariants
//
//   - No silent drops (invariant #7): every SERVFAIL response is preceded by a
//     slog.Error call.
//   - Every error names remediation (invariant #8): slog.Error lines carry a
//     "remediation" field.
//   - The Resolver interface keeps miekg/dns types inside this package boundary;
//     callers depend on the interface, not on miekg/dns.Server or miekg/dns.Msg
//     in exported symbols other than via the interface.
package dataplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/config"
	"protocolward.ai/ward/internal/decoy"
	adapter "protocolward.ai/ward/internal/model"
	"protocolward.ai/ward/internal/policy"
	"protocolward.ai/ward/pkg/detect"
	"protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

// ErrAlreadyServing is returned by a second call to Serve() on the same
// *Server. Remediation: create a new Server instance via NewServer if you
// need a fresh listener (invariant #8: every error names a remediation).
var ErrAlreadyServing = errors.New("dataplane: Serve already called on this Server — remediation: create a new Server via NewServer for each listener lifecycle")

// DEFERRED(slice-B): The Resolver interface exposes *dns.Msg as the request/response
// unit. This is a documented design choice, not a leak — DNS message framing is the
// natural unit of work at this boundary. Callers wiring a Resolver into the dataplane
// will need github.com/miekg/dns regardless. A pure-bytes or opaque Query type would
// add a serialization layer with no architectural benefit at the tracer tier.
type Resolver interface {
	Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
	Address() string
}

// SlowPathClassifier is the dataplane's view of pkg/model.Classifier — the
// Classify method only, with the same signature. *internal/model.Adapter
// (the sibling process) satisfies this interface directly, and so does
// *detect.Lexical (the in-process builtin detector). SP10c's slow-path fork
// depends on the interface, not a concrete type, so tests can inject a fake.
//
// A classifier that additionally implements model.Assessor (today only
// *detect.Lexical) is upgraded by the fork: it is called via Assess instead
// of Classify, and its non-benign results become flags. See
// Config.Classifier for the enforcement exclusion that goes with that.
// Everything below says "Classify call" for the sibling path and "Assess
// call" for the Assessor path; each is bounded by Config.ClassifyTimeout.
//
// The interface lives here (not in pkg/model) so internal/dataplane owns the
// abstraction it consumes — consistent with the policy.Matcher / Resolver
// patterns elsewhere in this package.
type SlowPathClassifier interface {
	Classify(ctx context.Context, in model.Input) (schema.Verdict, error)
}

// DecisionRecorder is the side-channel hook the dataplane calls after each
// policy decision so the dashboard (or any other read-only consumer) can
// surface the most-recent decision. nil is a valid value — the dataplane
// no-ops the call.
//
// `action` is the string form: "block" | "allow" | "forward" | "decoy".
// `matched` is the matched label/qname when applicable; empty for forward.
type DecisionRecorder interface {
	Record(qname, action, matched string)
}

// FlagRecorder is the side-channel sink for detector flags: a hostname whose
// Assessor result was non-benign. It mirrors DecisionRecorder so the
// dashboard (internal/web.FlagLog) can list flags without an upward import.
// nil is a valid Config.Flags value — the dataplane no-ops the call.
//
// Flags are observations, never enforcement (ADR-0006): by the time
// RecordFlag fires the query has already been forwarded and answered.
// reasonCodes are schema.Reason codes (stable machine strings), weight-
// descending, at most maxFlagReasons. client is the source IP without port.
type FlagRecorder interface {
	RecordFlag(qname, client string, score float64, reasonCodes []string)
}

// Config parameterises a Server instance.
type Config struct {
	// ListenAddr is the address to bind UDP and TCP listeners on (e.g. "127.0.0.1:53").
	// Use "host:0" for a random port (useful in tests).
	ListenAddr string

	// Resolvers is the ordered list of upstream resolvers for round-robin dispatch.
	// Must not be empty.
	Resolvers []Resolver

	// CounterSeed is the initial value of the round-robin counter. Set to a
	// non-zero value to start the rotation at a specific resolver. Defaults to 0.
	CounterSeed uint64

	// QueryTimeout bounds each upstream Query call. Defaults to 5s.
	QueryTimeout time.Duration

	// ShutdownTimeout bounds Shutdown(ctx). The caller's context deadline takes
	// precedence; this field is used when Shutdown is called without a deadline.
	ShutdownTimeout time.Duration

	// Engine, when non-nil, is consulted for every incoming query before
	// upstream dispatch. nil means "pure forwarder" (slice-A semantics preserved).
	Engine *policy.Engine

	// BlockResponse controls the wire shape returned on a blocklist hit
	// (mode=address with A/AAAA, or mode=nxdomain). Always populated by the
	// caller; an unset Mode panics at handle time per invariant #2.
	BlockResponse config.BlockResponseConfig

	// Decisions, when non-nil, is called once per query after the policy
	// decision is reached. Used by the dashboard /healthz endpoint to surface
	// the most-recent decision (internal/web.Store implements this). Decoupled
	// via interface so internal/dataplane has no upward import to internal/web.
	// Action is the string form: "block" | "allow" | "forward" | "decoy".
	Decisions DecisionRecorder

	// Flags, when non-nil, receives one RecordFlag call per non-benign
	// Assessor result from the slow-path fork (see Classifier). Classifiers
	// that implement only Classify (the sibling adapter) never produce flags.
	// The web.FlagLog (internal/web/handler.go) is the production
	// implementation; it caps reason codes with its own maxFlagReasons,
	// which mirrors this package's constant of the same name (defence in
	// depth — keep the two equal).
	Flags FlagRecorder

	// Classifier, when non-nil, enables the SP10c slow-path observe fork:
	// every forwarded qname (ActionForward branch — covers both blocklist-
	// miss and nil-Engine flows) is asynchronously handed to Classify (or,
	// for a model.Assessor, Assess) after the wire response returns. The current query is NEVER blocked by the
	// slow path; verdicts are observed and logged. nil disables the fork.
	//
	// On errors.Is(err, internal/model.ErrUnavailable): emit
	// `policy: model unavailable` exactly once (atomic latch) and skip every
	// subsequent forward — avoids per-query 1–4s waits on a dead child.
	// SP10c does not auto-restart; operator restarts ward to recover.
	//
	// Classifiers that also implement model.Assessor (the builtin detector)
	// are called via Assess, skip connectivityProbeZones, record flags via
	// Flags, and NEVER consult the Engine (DD8): their results are flags,
	// not decisions.
	//
	// TODO(enforcement): On the Classify-only (sibling) path the returned
	// policy.Decision is currently used for log attribution only — its
	// Action is NOT applied. Planned: a runtime-mutable learned-block
	// matcher that enforces VerdictMalicious / VerdictTelemetry on future
	// DNS queries. That enforcement applies to the Classify-only path only;
	// enforcing Assessor verdicts requires its own ADR (ADR-0006 D3, spec
	// D7 and invariant 1).
	Classifier SlowPathClassifier

	// ClassifyTimeout bounds each Classify or Assess call. Defaults to 4s — the Tier 2
	// upper bound per architecture.md. The slow-path context is decoupled
	// from the request context because the request has already been answered
	// when the fork fires; cancellation flows from Server.Shutdown via the
	// inFlight drain, not from the per-query ctx.
	ClassifyTimeout time.Duration

	// Decoys, when non-nil, is consulted BEFORE Engine.Decide. A decoy hit
	// short-circuits the policy engine: the dataplane emits a "policy: alert"
	// log line (slog.Warn) and writes the configured BlockResponse — the
	// query is NEVER forwarded upstream (forwarding would leak the decoy
	// hostname to the resolver). The short-circuit is documented in the
	// dns-forward and decoy-tripwire specs and represents the narrow reading
	// of invariant 2 (exhaustiveness applies to the Action enum switch in
	// Engine.Decide; the decoy alarm channel is parallel to allow/block).
	Decoys *decoy.Set
}

// Server is a DNS listener and query dispatcher. Create it with NewServer and
// start it with Serve. Stop it with Shutdown.
type Server struct {
	cfg     Config
	counter atomic.Uint64

	// udpSrv and tcpSrv are the two miekg DNS servers (one per transport).
	udpSrv *dns.Server
	tcpSrv *dns.Server

	// addr is the resolved listen address, set once the UDP server is ready.
	addrOnce sync.Once
	addr     string
	addrCh   chan struct{} // closed when addr is set

	// serveStarted is set true (via CompareAndSwap) by the first Serve call.
	// Any subsequent call returns ErrAlreadyServing immediately without blocking.
	serveStarted atomic.Bool

	// inFlight tracks queries currently being processed for graceful drain.
	// Slow-path classifyAsync goroutines also Add/Done here so Shutdown
	// drains them before returning.
	inFlight sync.WaitGroup

	// classifierDead latches true on the first model.ErrUnavailable from the
	// slow-path fork. Once latched, classifyAsync returns immediately without
	// dispatching, so a dead child does not pile up Classify calls.
	classifierDead atomic.Bool
}

// NewServer creates a Server from cfg. Returns an error if cfg is invalid.
func NewServer(cfg Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("dataplane.NewServer: ListenAddr must not be empty — remediation: set listen_addr in ward.yaml")
	}
	if len(cfg.Resolvers) == 0 {
		return nil, fmt.Errorf("dataplane.NewServer: Resolvers must not be empty — remediation: configure at least one upstream resolver")
	}
	// If any block-response path is reachable (policy Engine or decoy
	// short-circuit), BlockResponse.Mode must be set — otherwise the writer's
	// default: panic arm would fire on the first hit and the decoy alert log
	// would never be emitted (decoy-tripwire T8 Ralph I2).
	if cfg.Engine != nil || cfg.Decoys != nil {
		switch cfg.BlockResponse.Mode {
		case config.BlockResponseModeAddress, config.BlockResponseModeNXDOMAIN:
			// ok
		default:
			return nil, fmt.Errorf("dataplane.NewServer: BlockResponse.Mode must be %q or %q when Engine or Decoys is configured, got %q — remediation: set block_response.mode in ward.yaml (default %q)", config.BlockResponseModeAddress, config.BlockResponseModeNXDOMAIN, cfg.BlockResponse.Mode, config.BlockResponseModeAddress)
		}
	}
	if cfg.QueryTimeout == 0 {
		cfg.QueryTimeout = 5 * time.Second
	}
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = 5 * time.Second
	}
	if cfg.ClassifyTimeout == 0 {
		cfg.ClassifyTimeout = 4 * time.Second
	}

	s := &Server{
		cfg:    cfg,
		addrCh: make(chan struct{}),
	}
	s.counter.Store(cfg.CounterSeed)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleQuery)

	s.udpSrv = &dns.Server{
		Addr:    cfg.ListenAddr,
		Net:     "udp",
		Handler: mux,
		NotifyStartedFunc: func() {
			s.addrOnce.Do(func() {
				s.addr = s.udpSrv.PacketConn.LocalAddr().String()
				close(s.addrCh)
			})
		},
	}
	s.tcpSrv = &dns.Server{
		Addr:    cfg.ListenAddr,
		Net:     "tcp",
		Handler: mux,
	}

	return s, nil
}

// Addr returns the UDP listen address once the server is started, or "" if the
// server has not yet started.
func (s *Server) Addr() string {
	select {
	case <-s.addrCh:
		return s.addr
	default:
		return ""
	}
}

// Serve starts the UDP and TCP listeners. It blocks until both servers have
// stopped. Call Shutdown to initiate a graceful stop. A second concurrent or
// sequential call to Serve on the same *Server returns ErrAlreadyServing
// immediately without blocking.
func (s *Server) Serve() error {
	// CompareAndSwap false→true: only the first caller proceeds.
	// Any subsequent call (concurrent or sequential) gets false and returns
	// ErrAlreadyServing immediately.
	if !s.serveStarted.CompareAndSwap(false, true) {
		return ErrAlreadyServing
	}

	// We need both servers to share the same port. Bind UDP first (port 0 picks
	// a random port), then reuse that port for TCP.
	// Start UDP first, wait for the address, then start TCP on the same addr.

	udpReady := make(chan struct{})
	origNotify := s.udpSrv.NotifyStartedFunc
	s.udpSrv.NotifyStartedFunc = func() {
		origNotify()
		close(udpReady)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := s.udpSrv.ListenAndServe(); err != nil {
			// Ignore error on shutdown (dns.Server.ShutdownContext closes the conn).
			slog.Debug("udp server stopped", "error", err)
		}
	}()

	// Wait for UDP to bind so we can reuse the same port for TCP.
	<-udpReady
	s.tcpSrv.Addr = s.addr

	go func() {
		defer wg.Done()
		if err := s.tcpSrv.ListenAndServe(); err != nil {
			slog.Debug("tcp server stopped", "error", err)
		}
	}()

	wg.Wait()
	return nil
}

// Shutdown gracefully stops the server within the context deadline. In-flight
// queries are drained before returning.
func (s *Server) Shutdown(ctx context.Context) error {
	// Stop accepting new queries.
	udpErr := s.udpSrv.ShutdownContext(ctx)
	tcpErr := s.tcpSrv.ShutdownContext(ctx)

	// Drain in-flight queries within the context deadline.
	drained := make(chan struct{})
	go func() {
		s.inFlight.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-ctx.Done():
	}

	if udpErr != nil {
		return fmt.Errorf("dataplane shutdown (udp): %w", udpErr)
	}
	if tcpErr != nil {
		return fmt.Errorf("dataplane shutdown (tcp): %w", tcpErr)
	}
	return nil
}

// handleQuery is the miekg/dns handler for every incoming DNS query.
func (s *Server) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	s.inFlight.Add(1)
	defer s.inFlight.Done()

	// Invariant #7: catch-all panic recovery. The empty-Question guard below
	// handles the most predictable case; this defer handles anything else.
	defer s.recoverPanic(w, req)

	if len(req.Question) == 0 {
		s.writeFormatError(w, req)
		return
	}

	q := req.Question[0]
	qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	// Decoy short-circuit: fires BEFORE Engine.Decide so a decoy hit cannot
	// be masked by an allowlist override. A matched decoy emits a Warn-level
	// alert and writes the configured BlockResponse; the query is NEVER
	// forwarded (forwarding would leak the decoy hostname upstream).
	if s.cfg.Decoys != nil {
		if id, matched, ok := s.cfg.Decoys.Match(qname); ok {
			// LESSON (decoy-tripwire T8 Ralph I3): emit the alert BEFORE the
			// wire write. If writeBlockResponse panics (e.g. an unhandled
			// BlockResponse.Mode would hit the default: panic), the deferred
			// recoverPanic catches it and returns SERVFAIL — but the alert
			// log is the whole point of the feature, so it must be recorded
			// first. The wire write is best-effort secondary to the audit
			// trail. Block/allow attribution does NOT have this constraint
			// because those log lines are operator-facing diagnostics, not
			// security alerts.
			s.logDecoyAlert(w, q, qname, id, matched)
			s.writeBlockResponse(w, req)
			if s.cfg.Decisions != nil {
				s.cfg.Decisions.Record(qname, "decoy", matched)
			}
			return
		}
	}

	var d policy.Decision
	if s.cfg.Engine != nil {
		d = s.cfg.Engine.Decide(qname)
	}

	switch d.Action {
	case policy.ActionBlock:
		s.writeBlockResponse(w, req)
		s.logAttribution(w, q, qname, d)
		if s.cfg.Decisions != nil {
			s.cfg.Decisions.Record(qname, "block", d.MatchedLabel)
		}
		return
	case policy.ActionAllow:
		// LESSON (dashboard-healthz T5 Ralph B2): Record fires AFTER the wire
		// outcome (forwardUpstream returns) so last_decision reflects what
		// the client actually received, not just the policy decision that
		// was reached. For block the wire write happens above; for
		// allow/forward we wait until the upstream call has run.
		s.logAttribution(w, q, qname, d)
		s.forwardUpstream(w, req)
		if s.cfg.Decisions != nil {
			s.cfg.Decisions.Record(qname, "allow", d.MatchedLabel)
		}
	case policy.ActionForward:
		s.forwardUpstream(w, req)
		if s.cfg.Decisions != nil {
			s.cfg.Decisions.Record(qname, "forward", "")
		}
		// SP10c slow-path observe fork: only fires on a forward (the fast-path
		// miss). Block / allow short-circuited above; decoy short-circuited
		// before policy.Decide. nil-Engine produces a zero-value Decision
		// whose Action is ActionForward, so nil-Engine flows also reach here.
		if s.cfg.Classifier != nil {
			// Capture the client synchronously: the fork must not touch w.
			client := clientHost(w.RemoteAddr())
			s.inFlight.Add(1)
			go s.classifyAsync(qname, client)
		}
	default:
		panic(fmt.Sprintf("policy: missing handler for action %v (invariant #2 violation)", d.Action))
	}
}

// recoverPanic is the defer'd panic handler shared by handleQuery. Extracted
// from the inline defer for readability; slice-A behavior unchanged.
func (s *Server) recoverPanic(w dns.ResponseWriter, req *dns.Msg) {
	if r := recover(); r != nil {
		slog.Error("dataplane: handler panic recovered",
			"panic", fmt.Sprintf("%v", r),
			"remediation", "report this as a bug at the project repository — include the query if possible",
		)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(resp)
	}
}

// writeFormatError handles the qdcount=0 case. Matches slice-B exactly.
func (s *Server) writeFormatError(w dns.ResponseWriter, req *dns.Msg) {
	slog.Error("dataplane: received query with no question section",
		"src", w.RemoteAddr().String(),
		"remediation", "this is a malformed DNS message; no action needed unless frequent",
	)
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeFormatError)
	_ = w.WriteMsg(resp)
}

const blockResponseTTL = 60

// writeBlockResponse emits the wire response for a blocklist hit, shaped by
// the configured BlockResponseConfig. Both switches are exhaustive; the
// outer default panics on an unknown Mode to satisfy invariant #2.
//
// LESSON PRESERVED (slice-B T5 I1): miekg/dns's SetRcode internally calls
// SetReply, which resets Authoritative=false. AA/RA MUST be set AFTER the
// switch so they apply to every branch.
//
// LESSON PRESERVED (slice-B T8 I3): A/AAAA answer RRs preserve q.Qclass —
// a query with qclass=CH must get a Class=CH answer.
func (s *Server) writeBlockResponse(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	q := req.Question[0]

	switch s.cfg.BlockResponse.Mode {
	case config.BlockResponseModeNXDOMAIN:
		resp.SetRcode(req, dns.RcodeNameError)
	case config.BlockResponseModeAddress:
		switch q.Qtype {
		case dns.TypeA:
			resp.SetReply(req)
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: q.Qclass, Ttl: blockResponseTTL},
				A:   s.cfg.BlockResponse.A.AsSlice(),
			}}
		case dns.TypeAAAA:
			resp.SetReply(req)
			resp.Answer = []dns.RR{&dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: q.Qclass, Ttl: blockResponseTTL},
				AAAA: s.cfg.BlockResponse.AAAA.AsSlice(),
			}}
		default:
			resp.SetRcode(req, dns.RcodeNameError)
		}
	default:
		panic(fmt.Sprintf("config: missing handler for block_response.mode %q (invariant #2 violation)", s.cfg.BlockResponse.Mode))
	}

	// LESSON (slice-B T5 I1): SetRcode/SetReply resets Authoritative=false.
	// These flags MUST be set after the switch so they apply to every branch.
	resp.Authoritative = true
	resp.RecursionAvailable = false

	if err := w.WriteMsg(resp); err != nil {
		slog.Error("dataplane: failed to write block response",
			"error", err.Error(),
			"qname", strings.TrimSuffix(q.Name, "."),
			"remediation", "check the dns.ResponseWriter implementation — this is unexpected for an in-process responder",
		)
	}
}

// logDecoyAlert emits the "policy: alert" Warn line for a decoy hit. Warn
// is one level above the policy:blocked Info — a decoy hit is a higher-
// confidence threat signal; operators filtering on level>=warn catch
// alerts without an extra rule. (operator-confirmed 2026-05-25.)
func (s *Server) logDecoyAlert(w dns.ResponseWriter, q dns.Question, qname, decoyID, matched string) {
	src := ""
	if ra := w.RemoteAddr(); ra != nil {
		src = ra.String()
	}
	slog.Warn("policy: alert",
		"decoy_id", decoyID,
		"kind", "decoy",
		"qname", qname,
		"qtype", dns.TypeToString[q.Qtype],
		"matched", matched,
		"src", src,
		"remediation", "investigate the source host — a legitimate client should never query a decoy hostname",
	)
}

// logAttribution emits one INFO line per allow/block hit. Symmetric so
// "no silent overrides" (UX invariant #7 corollary) is enforced.
func (s *Server) logAttribution(w dns.ResponseWriter, q dns.Question, qname string, d policy.Decision) {
	src := ""
	if ra := w.RemoteAddr(); ra != nil {
		src = ra.String()
	}
	switch d.Action {
	case policy.ActionBlock:
		slog.Info("policy: blocked",
			"list_id", d.ListID,
			"kind", "block",
			"qname", qname,
			"qtype", dns.TypeToString[q.Qtype],
			"matched", d.MatchedLabel,
			"src", src,
			"remediation", "add to allowlist: "+qname,
		)
	case policy.ActionAllow:
		slog.Info("policy: allowed",
			"list_id", d.ListID,
			"kind", "allow",
			"qname", qname,
			"qtype", dns.TypeToString[q.Qtype],
			"matched", d.MatchedLabel,
			"src", src,
		)
	case policy.ActionForward:
		// no-op: forward is the silent path; the post-upstream "query" log
		// already records the outcome.
	default:
		panic(fmt.Sprintf("policy: missing logAttribution arm for action %v (invariant #2 violation)", d.Action))
	}
}

// forwardUpstream extracts the slice-A round-robin + retry block verbatim.
// No behavior change — mechanical move from handleQuery.
func (s *Server) forwardUpstream(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	n := uint64(len(s.cfg.Resolvers))

	idx := (s.counter.Add(1) - 1) % n
	resolver := s.cfg.Resolvers[idx]

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.QueryTimeout)
	defer cancel()

	resp, err := resolver.Query(ctx, req)
	if err != nil {
		if n > 1 {
			nextIdx := (idx + 1) % n
			nextResolver := s.cfg.Resolvers[nextIdx]
			resp, err = nextResolver.Query(ctx, req)
			if err == nil {
				resolver = nextResolver
			}
		}
		if err != nil {
			slog.Error("all upstream resolvers failed",
				"qname", req.Question[0].Name,
				"qtype", dns.TypeToString[req.Question[0].Qtype],
				"upstream", resolver.Address(),
				"error", err.Error(),
				"remediation", "check upstream resolver connectivity and ward.yaml configuration",
			)
			servfail := new(dns.Msg)
			servfail.SetRcode(req, dns.RcodeServerFailure)
			_ = w.WriteMsg(servfail)
			return
		}
	}

	rtt := time.Since(start)
	src := ""
	if ra := w.RemoteAddr(); ra != nil {
		src = ra.String()
	}
	slog.Info("query",
		"qname", req.Question[0].Name,
		"qtype", dns.TypeToString[req.Question[0].Qtype],
		"upstream", resolver.Address(),
		"rtt_ms", rtt.Milliseconds(),
		"rcode", dns.RcodeToString[resp.Rcode],
		"src", src,
	)

	_ = w.WriteMsg(resp)
}

// classifyAsync is the SP10c slow-path goroutine entry. Called as
// `go s.classifyAsync(qname, client)` from the ActionForward branch with
// s.inFlight.Add(1) already accounted; Done is deferred here so Shutdown's
// drain blocks until the fork completes. See Config.Classifier doc for the
// observe-only contract + the planned enforcement carry-forward.
//
// When the classifier also implements model.Assessor (the in-process
// builtin detector), Assess is called instead of Classify and a non-benign
// result is recorded via Config.Flags. Flags are never enforced.
func (s *Server) classifyAsync(qname, client string) {
	defer s.inFlight.Done()
	// DD6: an in-process classifier (model.builtin) has no process boundary,
	// so contain its panics here. Registered after inFlight.Done so it runs
	// first (LIFO) and Done still fires. The query was already answered.
	defer func() {
		if r := recover(); r != nil {
			// Bounded: the value is capped at 256 bytes and the stack at
			// ~2KB so a detector bug cannot flood the log. Reason.Detail is
			// never read here.
			slog.Error("policy: classifier panic recovered",
				"qname", qname,
				"panic", truncateForLog(fmt.Sprintf("%v", r), maxPanicValueBytes),
				"stack", truncateForLog(string(debug.Stack()), maxPanicStackBytes),
				"remediation", "report this as a bug at the project repository — include the qname; the query was answered normally and ward keeps running",
			)
		}
	}()
	if s.classifierDead.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ClassifyTimeout)
	defer cancel()

	var (
		verdict    schema.Verdict
		assessment *schema.Assessment
		err        error
	)
	if as, ok := s.cfg.Classifier.(model.Assessor); ok {
		if isConnectivityProbe(qname) {
			// DD9: an OS connectivity probe from a LAN client — never
			// assessed, so never flagged.
			slog.Debug("policy: classify skipped",
				"qname", qname,
				"reason", "os connectivity probe",
			)
			return
		}
		var a schema.Assessment
		a, err = as.Assess(ctx, model.Input{Hostname: qname})
		verdict = a.Verdict
		assessment = &a
	} else {
		verdict, err = s.cfg.Classifier.Classify(ctx, model.Input{Hostname: qname})
	}
	if err != nil {
		if errors.Is(err, detect.ErrInvalidHostname) {
			// Root queries ("" after the trailing-dot strip), IP literals,
			// control or non-ASCII bytes, malformed labels: normal DNS
			// traffic the lexical detector refuses to score. Quiet by
			// design — never a Warn, never the unavailable latch.
			slog.Debug("policy: classify skipped",
				"qname", qname,
				"reason", "not a scorable hostname",
			)
			return
		}
		if errors.Is(err, adapter.ErrUnavailable) {
			if s.classifierDead.CompareAndSwap(false, true) {
				slog.Error("policy: model unavailable",
					"qname", qname,
					"error", err.Error(),
					"remediation", "restart ward to reload the adapter — SP10c does not auto-restart the sibling",
				)
			}
			return
		}
		remediation := "investigate adapter logs — the failure is non-fatal but should not recur"
		if assessment != nil {
			// Builtin path: no adapter exists. detect.Assess returns
			// ctx.Err() on timeout or cancellation.
			remediation = "the built-in detector ran out of time or was cancelled; the query was answered normally — no action needed unless this recurs, then raise ClassifyTimeout or report a bug"
		}
		slog.Warn("policy: classify error",
			"qname", qname,
			"error", err.Error(),
			"remediation", remediation,
		)
		return
	}

	// Builtin (Assessor) path: flag-only by construction (ADR-0006
	// D3). The policy engine is deliberately NOT consulted (DD8):
	// DecideWithVerdict maps Malicious → ActionBlock, and planned enforcement will start
	// applying that Decision on the Classify path below. A detector flag
	// must never become a block without its own ADR. Flag attrs ride on the
	// single policy: classified line (one event, one line); only non-benign
	// results are flags.
	if assessment != nil {
		var flagAttrs []any
		if verdict != schema.VerdictBenign {
			codes := topReasonCodes(assessment.Reasons)
			if s.cfg.Flags != nil {
				s.cfg.Flags.RecordFlag(qname, client, assessment.Score, codes)
			}
			flagAttrs = []any{
				"score", assessment.Score,
				"reasons", codes,
				"client", client,
				"enforced", false,
				"remediation", "flagged, not blocked — add " + qname + " to a blocklist to enforce",
			}
		}
		s.logClassified(qname, verdict, policy.Decision{Action: policy.ActionForward, Kind: policy.KindNone}, flagAttrs...)
		return
	}

	// Sibling (Classify-only) path — unchanged from main (DoD 13-15).
	// DecideWithVerdict threads the verdict through the policy engine so the
	// Classifier→Verdict→Engine→Action chain (invariant 1) is exercised
	// end-to-end. With a nil Engine, skip the decide call and log the bare
	// verdict — there is no policy to consult.
	//
	// TODO(enforcement): d.Action is intentionally NOT applied here — the current
	// query has already been answered, and future-query enforcement is
	// deferred to the runtime-block matcher slice. The Decision is used for
	// log attribution only (kind + matched fields).
	if s.cfg.Engine == nil {
		s.logClassified(qname, verdict, policy.Decision{Action: policy.ActionForward, Kind: policy.KindNone})
		return
	}
	d := s.cfg.Engine.DecideWithVerdict(qname, verdict)
	s.logClassified(qname, verdict, d)
}

// logClassified emits the `policy: classified` line at a verdict-appropriate
// level: Malicious → Warn (matches decoy-alert convention), Telemetry → Info
// (matches policy:blocked), Benign → Debug (silent on default level). extra
// carries flag attributes on the Assessor path; the sibling path passes none
// so its line is unchanged (DoD bullets 13-15 grep it).
func (s *Server) logClassified(qname string, v schema.Verdict, d policy.Decision, extra ...any) {
	attrs := []any{
		"qname", qname,
		"verdict", verdictWire(v),
		"kind", d.Kind.String(),
		"matched", d.MatchedLabel,
	}
	attrs = append(attrs, extra...)
	switch v {
	case schema.VerdictMalicious:
		slog.Warn("policy: classified", attrs...)
	case schema.VerdictTelemetry:
		slog.Info("policy: classified", attrs...)
	case schema.VerdictBenign:
		slog.Debug("policy: classified", attrs...)
	default:
		// Unreachable in well-formed flows — pkg/schema's JSON decoder
		// rejects unknown variants at the wire boundary, so by the time a
		// Verdict reaches this method it is one of the three known values.
		// Logged at Warn so an adapter bug surfaces rather than silently
		// dropping.
		slog.Warn("policy: classified",
			append(attrs, "warning", fmt.Sprintf("unknown schema.Verdict %d", int(v)))...,
		)
	}
}

// verdictWire returns the lowercase wire form of the verdict, matching
// pkg/schema.Verdict.MarshalJSON. Used in log lines for consistency with the
// `kind` / `action` lowercase convention already in use in this package.
func verdictWire(v schema.Verdict) string {
	switch v {
	case schema.VerdictBenign:
		return "benign"
	case schema.VerdictTelemetry:
		return "telemetry"
	case schema.VerdictMalicious:
		return "malicious"
	default:
		return fmt.Sprintf("unknown(%d)", int(v))
	}
}

// maxFlagReasons bounds the reason codes carried on one flag (log line and
// dashboard row). Reasons arrive weight-descending (pkg/schema contract),
// so the first N are the top N. internal/web/handler.go keeps a deliberate
// twin of this constant (the web.FlagLog re-truncates as defence in depth);
// change both together.
const maxFlagReasons = 3

// Bounds for the recovered-panic log attrs.
const (
	maxPanicValueBytes = 256
	maxPanicStackBytes = 2048
)

// truncateForLog caps s at max bytes (cut back to a rune boundary) and marks
// the cut so a truncated value is never mistaken for a complete one.
func truncateForLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.ToValidUTF8(s[:max], "") + "…(truncated)"
}

// topReasonCodes returns the codes of the first maxFlagReasons reasons.
// Only codes are surfaced — never Reason.Detail — so no free text reaches
// logs or the dashboard. nil/empty input yields an empty, non-nil slice.
func topReasonCodes(rs []schema.Reason) []string {
	n := min(len(rs), maxFlagReasons)
	codes := make([]string, 0, n)
	for _, r := range rs[:n] {
		codes = append(codes, r.Code)
	}
	return codes
}

// clientHost returns the host part of a remote address ("127.0.0.1" for
// "127.0.0.1:53124"), the raw string when it has no port, or "" for nil.
func clientHost(ra net.Addr) string {
	if ra == nil {
		return ""
	}
	s := ra.String()
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

// connectivityProbeZones are operating-system connectivity-check /
// captive-portal zones that LAN clients poll on their own. ward runs on a
// Linux or macOS host but answers DNS for every client on the LAN, so these
// probes reach the detector even though the ward host never sends them. A
// listed zone (and every name under it — pkg/detect scores only the
// registrable label, so subdomains share the zone's score) is never
// assessed on the Assessor path, so it is never flagged (DD9).
//
// Evidence-only: a zone is listed only when detect.New() flags it.
// Measured 2026-10-05 (T_mal 0.50):
//
//	msftncsi.com                   0.600  Malicious  → listed
//	msftconnecttest.com            0.234  Benign
//	connectivity-check.ubuntu.com  0.176  Benign
//	captive.g.aaplimg.com          0.166  Benign
//	nmcheck.gnome.org              0.107  Benign
//	connectivitycheck.android.com  0.093  Benign
//	network-test.debian.org        0.072  Benign
//	connectivitycheck.gstatic.com  0.003  Benign
//	captive.apple.com, detectportal.firefox.com, clients3.google.com  0.000
//
// TestFlags_RealDetector_ConnectivityProbes_NeverFlagged pins that every
// unlisted row stays non-flagging (it does not pin the scores), so a
// recalibration that flags one fails CI; add its zone here with the new
// score. TestFlags_RealDetector_Msftncsi_StillMalicious catches the
// opposite staleness: the listed zone no longer needing the exemption.
var connectivityProbeZones = []string{"msftncsi.com"}

// isConnectivityProbe reports whether qname (already lowercased, trailing
// dot stripped by handleQuery) is a listed zone or a name under one.
func isConnectivityProbe(qname string) bool {
	for _, z := range connectivityProbeZones {
		if qname == z || strings.HasSuffix(qname, "."+z) {
			return true
		}
	}
	return false
}

// dispatchForTest is a test seam: it runs the same Action switch as
// handleQuery, given a pre-computed Decision. Used by the invariant-#2
// runtime-backstop test in handlequery_internal_test.go (which is in
// the same package and so can see unexported symbols).
func (s *Server) dispatchForTest(w dns.ResponseWriter, req *dns.Msg, d policy.Decision) {
	switch d.Action {
	case policy.ActionBlock:
		s.writeBlockResponse(w, req)
	case policy.ActionAllow, policy.ActionForward:
		// not exercised by the UnknownAction test
	default:
		panic(fmt.Sprintf("policy: missing handler for action %v (invariant #2 violation)", d.Action))
	}
}
