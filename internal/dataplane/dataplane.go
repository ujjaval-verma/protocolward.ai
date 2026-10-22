// SPDX-License-Identifier: Apache-2.0

// Package dataplane implements the DNS listener and query dispatcher for ward.
//
// It listens on UDP and TCP (via miekg/dns.Server), dispatches each incoming
// query to a round-robin selection of Resolvers, retries once on the next
// resolver on failure, and returns SERVFAIL if all attempts fail. Both
// attempts share one end-to-end budget (Config.QueryTimeout).
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
	"syscall"
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

// ErrListenerStopped is wrapped by the error Serve returns when a listener
// that was bound successfully later stops with an error (as opposed to a
// bind failure). Test with errors.Is.
var ErrListenerStopped = errors.New("stopped")

// ErrDrainTimeout is returned (wrapped) by Shutdown when its context ends
// before in-flight queries and classifications have drained. The message
// names how many classifications were still running.
var ErrDrainTimeout = errors.New("dataplane: shutdown drain budget elapsed")

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

	// QueryTimeout is the end-to-end upstream budget for one client query,
	// failover included (timeouts.query in ward.yaml). With two or more
	// Resolvers, the first attempt gets at most half of it; the retry on the
	// next resolver gets whatever remains. Worst case before SERVFAIL is
	// QueryTimeout, not QueryTimeout per attempt. Defaults to 5s.
	QueryTimeout time.Duration

	// ShutdownTimeout bounds the drain Serve runs after a listener error
	// (abort). Shutdown(ctx) itself is bounded only by ctx.
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
	// At most maxClassifyInFlight classifications run at once; past that a
	// forwarded name is not classified and the drop is counted and logged
	// (`policy: classify dropped`, rate-limited, with a running total).
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

	// ClassifyTimeout bounds each Assess call, and for a Classify-only
	// (external) classifier the wait for the adapter's slot plus its check
	// before the request is written (a call still waiting when it ends is
	// dropped and counted, not a failure). An exchange already on the wire
	// is bounded by the adapter's reply timeout
	// (internal/model.DefaultReplyTimeout) instead, so one call can hold its
	// slow-path slot for up to ClassifyTimeout plus that timeout. Defaults
	// to 4s — the Tier 2 upper bound per architecture.md. The slow-path
	// context is decoupled from the request context because the request has
	// already been answered when the fork fires. For a Classify-only (external) classifier it
	// derives from the server's stop context instead: Server.Shutdown
	// cancels it, so a classification still waiting for the sibling adapter
	// is skipped at once and the inFlight drain waits only for calls already
	// running. An Assessor's context derives from context.Background(), so
	// Shutdown drains it.
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

	// addr is the resolved listen address. It is set once BOTH listeners
	// are serving (listenersUp reaches 2), so a non-empty Addr() means
	// Shutdown stops both transports.
	addrOnce    sync.Once
	addr        string
	addrCh      chan struct{} // closed when addr is set
	listenersUp atomic.Int32

	// listenUDP and listenTCP bind the sockets in Serve. NewServer sets them
	// to net.ListenPacket and net.Listen; internal tests replace them to
	// force bind errors.
	listenUDP func(network, address string) (net.PacketConn, error)
	listenTCP func(network, address string) (net.Listener, error)

	// serveStarted is set true (via CompareAndSwap) by the first Serve call.
	// Any subsequent call returns ErrAlreadyServing immediately without blocking.
	serveStarted atomic.Bool

	// inFlight tracks queries currently being processed for graceful drain.
	// Slow-path classifyAsync goroutines also Add/Done here so Shutdown
	// drains them before returning.
	inFlight sync.WaitGroup
	// inFlightN mirrors inFlight so Shutdown can tell "nothing left" from
	// "still running" when its context is already done. Use enterFlight and
	// leaveFlight, never inFlight directly.
	inFlightN atomic.Int64

	// classifierDead latches true on the first model.ErrUnavailable from the
	// slow-path fork. Once latched, classifyAsync returns immediately without
	// dispatching, so a dead child does not pile up Classify calls.
	classifierDead atomic.Bool

	// classifySlots bounds the classifyAsync goroutines alive at once to
	// maxClassifyInFlight. handleQuery takes a slot without blocking and
	// classifyAsync gives it back; with no free slot the classification is
	// dropped, never queued.
	classifySlots chan struct{}

	// stopCtx is the parent of every Classify-only (external) classify
	// context. Shutdown cancels it (stopCancel is idempotent) so queued
	// external-classifier calls skip instead of running out the drain
	// budget.
	stopCtx    context.Context
	stopCancel context.CancelFunc

	// classifyDropped counts classifications that did not run: no free
	// slot, or the sibling adapter was still busy when the classify timeout
	// ended (internal/model.ErrSkipped). Reported, with the running total,
	// by the rate-limited `policy: classify dropped` line.
	classifyDropped atomic.Uint64

	// classifyDropLoggedAt is the UnixNano time of the last
	// `policy: classify dropped` line; 0 means none yet.
	classifyDropLoggedAt atomic.Int64
}

// maxClassifyInFlight caps concurrent slow-path classifications. Past it a
// forwarded name is answered normally but not classified, and the drop is
// counted. 64 keeps a burst from becoming a goroutine flood while leaving
// headroom: the built-in detector finishes in microseconds, so its slots
// rarely fill, and a serialised sibling at ~60 ms per call clears 64
// waiters inside the default 4 s ClassifyTimeout. A constant, not a
// ward.yaml key: there is no evidence yet that operators need to tune it.
const maxClassifyInFlight = 64

// classifyDropLogEvery rate-limits the `policy: classify dropped` line: the
// first drop logs at once, later drops at most once per interval.
const classifyDropLogEvery = time.Minute

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

	stopCtx, stopCancel := context.WithCancel(context.Background())
	s := &Server{
		stopCtx:       stopCtx,
		stopCancel:    stopCancel,
		cfg:           cfg,
		addrCh:        make(chan struct{}),
		listenUDP:     net.ListenPacket,
		listenTCP:     net.Listen,
		classifySlots: make(chan struct{}, maxClassifyInFlight),
	}
	s.counter.Store(cfg.CounterSeed)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleQuery)

	s.udpSrv = &dns.Server{
		Addr:              cfg.ListenAddr,
		Net:               "udp",
		Handler:           mux,
		NotifyStartedFunc: s.listenerStarted,
	}
	s.tcpSrv = &dns.Server{
		Addr:              cfg.ListenAddr,
		Net:               "tcp",
		Handler:           mux,
		NotifyStartedFunc: s.listenerStarted,
	}

	return s, nil
}

// Addr returns the shared UDP/TCP listen address once both listeners are
// serving, or "" before that. It is not cleared when Serve returns.
func (s *Server) Addr() string {
	select {
	case <-s.addrCh:
		return s.addr
	default:
		return ""
	}
}

// listenerStarted runs from each miekg server's NotifyStartedFunc. The
// second call means both transports are serving: it logs `dns: listening`,
// the post-bind readiness line, and publishes the address.
func (s *Server) listenerStarted() {
	if s.listenersUp.Add(1) == 2 {
		s.addrOnce.Do(func() {
			s.addr = s.udpSrv.PacketConn.LocalAddr().String()
			slog.Info("dns: listening", "addr", s.addr, "transports", "udp+tcp")
			close(s.addrCh)
		})
	}
}

// bindAttempts bounds the retry in bind when ListenAddr asks for an
// ephemeral port (":0"). The kernel picks the UDP port; the TCP listener must
// take the same number, which another socket may already hold.
const bindAttempts = 8

// bind opens the UDP socket on cfg.ListenAddr, then the TCP listener on the
// same host and port. On a TCP failure it closes the UDP socket. When the
// configured port is 0 and the TCP twin is taken (EADDRINUSE), it retries
// with a fresh UDP port, up to bindAttempts times. A fixed port is never
// retried. Errors wrap the net error, so errors.Is(err, syscall.EADDRINUSE)
// holds for a taken port.
func (s *Server) bind() (net.PacketConn, net.Listener, error) {
	attempts := 1
	if _, port, err := net.SplitHostPort(s.cfg.ListenAddr); err == nil && port == "0" {
		attempts = bindAttempts
	}
	var err error
	for range attempts {
		var pc net.PacketConn
		pc, err = s.listenUDP("udp", s.cfg.ListenAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("dataplane: %w", err)
		}
		var ln net.Listener
		ln, err = s.listenTCP("tcp", pc.LocalAddr().String())
		if err == nil {
			return pc, ln, nil
		}
		_ = pc.Close()
		if !errors.Is(err, syscall.EADDRINUSE) {
			break
		}
	}
	return nil, nil, fmt.Errorf("dataplane: %w", err)
}

// Serve binds the UDP and TCP listeners on one port, then serves both.
//
// A bind failure returns at once; the error wraps the net error, so
// errors.Is(err, syscall.EADDRINUSE) holds for a taken port. Once both
// listeners are bound, Serve blocks until both have stopped. It returns nil
// when they stopped because of Shutdown. If either listener stops with an
// error, Serve stops the other, drains in-flight queries (bounded by
// Config.ShutdownTimeout) and returns that first error.
//
// A second concurrent or sequential call to Serve on the same *Server
// returns ErrAlreadyServing immediately without blocking.
func (s *Server) Serve() error {
	// CompareAndSwap false→true: only the first caller proceeds.
	if !s.serveStarted.CompareAndSwap(false, true) {
		return ErrAlreadyServing
	}

	pc, ln, err := s.bind()
	if err != nil {
		s.stopCancel() // nothing is serving; release the stop context
		return err
	}
	local := pc.LocalAddr().String()
	s.udpSrv.PacketConn = pc
	s.tcpSrv.Listener = ln

	type stopped struct {
		transport string
		err       error
	}
	done := make(chan stopped, 2)
	go func() { done <- stopped{"udp", s.udpSrv.ActivateAndServe()} }()
	go func() { done <- stopped{"tcp", s.tcpSrv.ActivateAndServe()} }()

	var first error
	for range 2 {
		r := <-done
		if r.err == nil || first != nil {
			continue // clean stop, or the peer we are already aborting
		}
		first = fmt.Errorf("dataplane: %s listener on %s %w: %w", r.transport, local, ErrListenerStopped, r.err)
		s.abort(pc, ln)
	}
	return first
}

// abort stops both listeners after one of them failed. Closing the sockets
// first unblocks a peer that has not reached its serve loop yet (miekg's
// ShutdownContext returns "server not started" and would leave it running).
// Shutdown then drains in-flight queries, including classifyAsync goroutines,
// before Serve returns.
func (s *Server) abort(pc net.PacketConn, ln net.Listener) {
	_ = pc.Close()
	_ = ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	defer cancel()
	if err := s.Shutdown(ctx); errors.Is(err, ErrDrainTimeout) {
		// Other Shutdown errors stay discarded: the listener error is what
		// Serve returns. The stuck work may be a query handler rather than
		// a classification, so the remediation does not blame the classifier.
		slog.Warn("dataplane: shutdown drain incomplete",
			"error", err.Error(),
			"remediation", "in-flight queries or classifications were still running when timeouts.shutdown ran out while stopping after a listener error; the error counts the classifications (0 means a query, not the classifier, was stuck); raise timeouts.shutdown in ward.yaml if this recurs",
		)
	}
}

// Shutdown gracefully stops the server within the context deadline.
// In-flight queries and in-process classifications are drained before
// returning; calls still waiting for an external classifier are skipped.
// If ctx ends first, the error wraps ErrDrainTimeout and names the
// classifications still running; Shutdown does not log it.
func (s *Server) Shutdown(ctx context.Context) error {
	// Cancel queued and future external-classifier calls first so the drain
	// below waits only for calls already running. Safe to call repeatedly.
	s.stopCancel()

	// Stop accepting new queries.
	udpErr := s.udpSrv.ShutdownContext(ctx)
	tcpErr := s.tcpSrv.ShutdownContext(ctx)

	// Drain in-flight queries within the context deadline.
	drained := make(chan struct{})
	go func() {
		s.inFlight.Wait()
		close(drained)
	}()
	var errs []error
	select {
	case <-drained:
	case <-ctx.Done():
		// ctx may already have been done when the select ran, with nothing
		// left to drain (select picks among ready cases at random): report
		// a timeout only when work is really still running.
		if s.inFlightN.Load() > 0 {
			errs = append(errs, fmt.Errorf("%w: %d classification(s) still running: %w",
				ErrDrainTimeout, len(s.classifySlots), ctx.Err()))
		}
	}
	if udpErr != nil {
		errs = append(errs, fmt.Errorf("dataplane shutdown (udp): %w", udpErr))
	}
	if tcpErr != nil {
		errs = append(errs, fmt.Errorf("dataplane shutdown (tcp): %w", tcpErr))
	}
	return errors.Join(errs...)
}

func (s *Server) enterFlight() {
	s.inFlightN.Add(1)
	s.inFlight.Add(1)
}

func (s *Server) leaveFlight() {
	s.inFlight.Done()
	s.inFlightN.Add(-1)
}

// handleQuery is the miekg/dns handler for every incoming DNS query.
func (s *Server) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	s.enterFlight()
	defer s.leaveFlight()

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
			select {
			case s.classifySlots <- struct{}{}:
				s.enterFlight()
				go s.classifyAsync(qname, client)
			default:
				s.noteClassifyDropped(qname, "slow path at capacity")
			}
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

// forwardUpstream sends req to the next resolver in round-robin order and,
// on error, retries once on the resolver after it. Both attempts share one
// QueryTimeout deadline. With a fallback configured, the first attempt is
// capped at half the budget so a hanging primary still leaves the fallback
// time to answer; a primary that fails fast leaves the fallback
// everything that remains.
func (s *Server) forwardUpstream(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	n := uint64(len(s.cfg.Resolvers))

	idx := (s.counter.Add(1) - 1) % n
	resolver := s.cfg.Resolvers[idx]

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.QueryTimeout)
	defer cancel()

	firstCtx := ctx
	if n > 1 {
		var cancelFirst context.CancelFunc
		firstCtx, cancelFirst = context.WithTimeout(ctx, s.cfg.QueryTimeout/2)
		defer cancelFirst()
	}

	resp, err := resolver.Query(firstCtx, req)
	if err != nil {
		if n > 1 {
			nextIdx := (idx + 1) % n
			nextResolver := s.cfg.Resolvers[nextIdx]
			firstResolver, firstErr := resolver, err
			slog.Warn("upstream attempt failed; retrying on next resolver",
				"qname", req.Question[0].Name,
				"upstream", firstResolver.Address(),
				"next", nextResolver.Address(),
				"timed_out", errors.Is(firstErr, context.DeadlineExceeded),
				"error", firstErr.Error(),
				"remediation", "check connectivity to this upstream resolver, or remove it from upstreams in ward.yaml; if the link is slow, raise timeouts.query",
			)
			resp, err = nextResolver.Query(ctx, req)
			resolver = nextResolver
			if err != nil {
				slog.Error("all upstream resolvers failed",
					"qname", req.Question[0].Name,
					"qtype", dns.TypeToString[req.Question[0].Qtype],
					"upstream", resolver.Address(),
					"error", err.Error(),
					"first_upstream", firstResolver.Address(),
					"first_error", firstErr.Error(),
					"remediation", "check upstream resolver connectivity and ward.yaml configuration",
				)
			}
		} else {
			slog.Error("all upstream resolvers failed",
				"qname", req.Question[0].Name,
				"qtype", dns.TypeToString[req.Question[0].Qtype],
				"upstream", resolver.Address(),
				"error", err.Error(),
				"remediation", "check upstream resolver connectivity and ward.yaml configuration",
			)
		}
		if err != nil {
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
// `go s.classifyAsync(qname, client)` from the ActionForward branch with a
// classifySlots slot taken and s.inFlight.Add(1) already accounted; both
// are released here, so Shutdown's drain blocks until the fork completes.
// See Config.Classifier doc for the observe-only contract + the planned
// enforcement carry-forward.
//
// When the classifier also implements model.Assessor (the in-process
// builtin detector), Assess is called instead of Classify and a non-benign
// result is recorded via Config.Flags. Flags are never enforced.
func (s *Server) classifyAsync(qname, client string) {
	defer s.leaveFlight()
	defer func() { <-s.classifySlots }()
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
	// Only a call that may wait for the external classifier's slot is
	// cancelled by Shutdown (stopCtx): that wait is what would otherwise
	// run out the drain budget. An in-process Assessor has no slot and
	// finishes in microseconds, so a fork that already started is drained,
	// not cancelled, and its flag is recorded.
	parent := s.stopCtx
	as, isAssessor := s.cfg.Classifier.(model.Assessor)
	if isAssessor {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, s.cfg.ClassifyTimeout)
	defer cancel()

	var (
		verdict    schema.Verdict
		assessment *schema.Assessment
		err        error
	)
	if isAssessor {
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
		if errors.Is(err, adapter.ErrSkipped) {
			// The sibling was busy with earlier calls until this call's
			// timeout ended; nothing was sent to it. A drop, not a failure:
			// no latch, no per-call Warn.
			if s.stopCtx.Err() != nil {
				// Shutdown cancelled it: expected, so counted but silent.
				s.classifyDropped.Add(1)
				slog.Debug("policy: classify skipped",
					"qname", qname,
					"reason", "server shutting down",
				)
				return
			}
			s.noteClassifyDropped(qname, "classifier busy past the classify timeout")
			return
		}
		if errors.Is(err, adapter.ErrUnavailable) {
			if s.classifierDead.CompareAndSwap(false, true) {
				remediation := "restart ward to reload the adapter — SP10c does not auto-restart the sibling"
				if errors.Is(err, adapter.ErrNoReply) {
					remediation = fmt.Sprintf("the model accepted a request but did not reply within %s, so ward stopped it; check the model process for a hang or overload, then restart ward — answers are unaffected", adapter.DefaultReplyTimeout)
				}
				slog.Error("policy: model unavailable",
					"qname", qname,
					"error", err.Error(),
					"remediation", remediation,
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

// ClassifyDropped returns the number of classifications that did not run
// since the server was created: no free slot, or the external classifier
// skipped the call (busy past the classify timeout, or shutting down). It
// only increases. Safe for concurrent use; read by the /healthz handler.
func (s *Server) ClassifyDropped() uint64 { return s.classifyDropped.Load() }

// Values returned by Server.ClassifierState, reported as /healthz
// classifier.
const (
	// ClassifierStateNone: no slow-path classifier is configured.
	ClassifierStateNone = "none"
	// ClassifierStateOK: a classifier is configured and has not been
	// reported unavailable.
	ClassifierStateOK = "ok"
	// ClassifierStateUnavailable: the model was reported unavailable
	// (`policy: model unavailable`) and classification is off until ward
	// restarts. Answers are unaffected.
	ClassifierStateUnavailable = "unavailable"
)

// ClassifierState reports whether slow-path classification is configured
// and still running: ClassifierStateNone, ClassifierStateOK or
// ClassifierStateUnavailable. Once unavailable it stays so (no
// auto-restart). Safe for concurrent use; read by the /healthz handler.
func (s *Server) ClassifierState() string {
	switch {
	case s.cfg.Classifier == nil:
		return ClassifierStateNone
	case s.classifierDead.Load():
		return ClassifierStateUnavailable
	default:
		return ClassifierStateOK
	}
}

// noteClassifyDropped counts one classification that did not run and emits
// `policy: classify dropped` on the first drop and then at most once per
// classifyDropLogEvery, so a burst cannot flood the log. Each line carries
// the running total; drops between lines are counted, not lost.
func (s *Server) noteClassifyDropped(qname, reason string) {
	total := s.classifyDropped.Add(1)
	now := time.Now().UnixNano()
	last := s.classifyDropLoggedAt.Load()
	// now < last means the wall clock stepped back: log and restart the
	// interval rather than stay quiet until the clock catches up.
	if last != 0 && now >= last && now-last < int64(classifyDropLogEvery) {
		slog.Debug("policy: classify drop not logged",
			"qname", qname,
			"reason", reason,
			"dropped_total", total,
		)
		return
	}
	if !s.classifyDropLoggedAt.CompareAndSwap(last, now) {
		return // another goroutine logged this interval
	}
	slog.Warn("policy: classify dropped",
		"qname", qname,
		"reason", reason,
		"dropped_total", total,
		"remediation", "the query was answered normally; only its classification was skipped. Drops during a burst are expected. If dropped_total keeps rising, the classifier cannot keep up: use the built-in detector (model: {builtin: lexical}) or a faster model command",
	)
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
