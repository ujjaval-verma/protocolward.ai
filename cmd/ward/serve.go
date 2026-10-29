// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"protocolward.ai/ward/internal/allowlist"
	"protocolward.ai/ward/internal/config"
	"protocolward.ai/ward/internal/dataplane"
	"protocolward.ai/ward/internal/decoy"
	"protocolward.ai/ward/internal/hostlist"
	"protocolward.ai/ward/internal/model"
	"protocolward.ai/ward/internal/obs"
	"protocolward.ai/ward/internal/policy"
	"protocolward.ai/ward/internal/upstream"
	"protocolward.ai/ward/internal/web"
	"protocolward.ai/ward/pkg/detect"
)

// dashListen pre-binds the dashboard TCP listener so startup-time bind
// failures surface synchronously (not via the goroutine that calls Serve).
func dashListen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// requireLoopbackDashAddr returns nil iff addr's host is a loopback literal
// (127.0.0.1, ::1, or "localhost"). The dashboard surfaces DNS-decision data
// (qnames in /healthz and the HTML decisions table); invariant 4 forbids
// flow data from leaving the device. The HTTP route exception is justified
// only by the loopback constraint; see internal/web package doc.
func requireLoopbackDashAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid --dash-listen-addr %q: %w", addr, err)
	}
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return nil
	}
	return fmt.Errorf("--dash-listen-addr %q is non-loopback; invariant 4 requires loopback bind (127.0.0.1, ::1, or localhost)", addr)
}

// dashboardListenAddr is the default dashboard bind, per ADR-0001 D12.
// Fixed today; a dashboard config option (config-file override) is planned.
// Loopback-only is load-bearing — see internal/web package doc.
const dashboardListenAddr = "127.0.0.1:18987"

// serveError carries an exit code and a structured remediation hint so callers
// can surface the right code without calling os.Exit inside library code.
// Invariant #8: every error names a remediation.
type serveError struct {
	Code        int
	Message     string
	Remediation string
}

func (e *serveError) Error() string {
	if e.Remediation != "" {
		return fmt.Sprintf("%s — remediation: %s", e.Message, e.Remediation)
	}
	return e.Message
}

// serveOpts holds the parsed flags for the serve subcommand.
type serveOpts struct {
	configPath string
	// dashListenAddr overrides the dashboard bind. Empty means use the
	// dashboardListenAddr default (127.0.0.1:18987). Tests set this to a
	// free ephemeral address ("127.0.0.1:0") so parallel test runs don't
	// collide on the hardcoded production port (Ralph B1).
	dashListenAddr string
	// listenAddr overrides listen: from ward.yaml for this run. Empty means
	// use ward.yaml. Unlike ward.yaml's listen:, port 0 is allowed: the
	// kernel picks the port and ward holds it (tests rely on this).
	listenAddr string
	// newDataplane overrides the dataplane constructor. Nil means
	// dataplane.NewServer. Only tests set it (to inject an init failure).
	newDataplane func(dataplane.Config) (*dataplane.Server, error)
	// notifySignals overrides how the second-signal exit hatch subscribes to
	// SIGINT/SIGTERM. Nil means notifyShutdownSignals. Only tests set it.
	notifySignals signalNotifier
	// exit overrides the hatch's exit function. Nil means os.Exit. Only tests
	// set it.
	exit func(int)
}

// signalNotifier subscribes to the shutdown signals and returns the channel
// they arrive on and a function that unsubscribes.
type signalNotifier func() (<-chan os.Signal, func())

// notifyShutdownSignals is the production signalNotifier: SIGINT and SIGTERM
// on a 1-buffered channel.
func notifyShutdownSignals() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	return ch, func() { signal.Stop(ch) }
}

// exitHatch is the second-signal escape hatch. Once armed, a SIGINT or
// SIGTERM closes the dashboard and exits 130 at once, skipping the drain and
// every deferred cleanup. It does not call Adapter.Close: Close waits behind
// an in-flight Classify and then up to CloseGrace for the child, which would
// defeat an immediate exit. When ward exits the kernel closes the child's
// stdin, the same EOF Close sends, and init reaps the orphan.
//
// arm and disarm must be ordered by happens-before (the same goroutine or a
// channel handoff); the hatch has no mutex.
type exitHatch struct {
	notify   signalNotifier
	exit     func(int)
	done     chan struct{} // closed by disarm; nil until armed
	finished chan struct{} // closed when the hatch goroutine has returned
	disarmed bool
}

// newExitHatch returns an unarmed hatch. A nil notify means
// notifyShutdownSignals; a nil exit means os.Exit.
func newExitHatch(notify signalNotifier, exit func(int)) *exitHatch {
	if notify == nil {
		notify = notifyShutdownSignals
	}
	if exit == nil {
		exit = os.Exit
	}
	return &exitHatch{notify: notify, exit: exit}
}

// arm subscribes to the shutdown signals and starts the goroutine that fires
// on the next one. The subscription ends when budget elapses or at disarm,
// whichever comes first.
func (h *exitHatch) arm(budget time.Duration, dash io.Closer) {
	sigCh, stop := h.notify()
	h.done, h.finished = make(chan struct{}), make(chan struct{})
	done, finished := h.done, h.finished
	fire := func() {
		_ = dash.Close()
		// Second signal during shutdown → immediate exit (130 = 128+SIGINT).
		h.exit(130)
	}
	go func() {
		// Registered first so it runs last: disarm cannot return while the
		// goroutine is still subscribed.
		defer close(finished)
		defer stop()
		select {
		case <-sigCh:
			fire()
		case <-time.After(budget):
			// Drain budget elapsed; outer logic handles the forced close.
		case <-done:
			// A signal that arrived before disarm still fires.
			select {
			case <-sigCh:
				fire()
			default:
			}
		}
	}()
}

// disarm ends the subscription and waits for the hatch goroutine to return,
// so once it returns nothing is subscribed and exit can no longer be called.
// It is a no-op on an unarmed hatch and safe to call more than once.
func (h *exitHatch) disarm() {
	if h.done == nil {
		return
	}
	if !h.disarmed {
		h.disarmed = true
		close(h.done)
	}
	<-h.finished
}

// lipgloss styles for startup-error stderr output.
// Palette: amber label, plain text for message and remediation. No emojis.
// Per DESIGN.md: calm, direct, technically honest.
var (
	styleLabel       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214")) // amber
	stylePlain       = lipgloss.NewStyle()
	styleRemediation = lipgloss.NewStyle().Foreground(lipgloss.Color("250")) // light grey
)

// printStartupError prints a lipgloss-styled startup error to stderr AND emits
// a structured slog line. Both channels are required.
func printStartupError(label, message, remediation string) {
	fmt.Fprintln(os.Stderr, styleLabel.Render(label))
	fmt.Fprintln(os.Stderr, stylePlain.Render(message))
	if remediation != "" {
		fmt.Fprintln(os.Stderr, styleRemediation.Render("remediation: "+remediation))
	}
	slog.Error("startup error",
		"label", label,
		"error", message,
		"remediation", remediation,
	)
}

// resolveConfigPath implements the §5 search order:
//
//  1. --config flag (non-empty path, returned as-is — missing file is a fatal
//     error surfaced by Load, not here).
//  2. $XDG_CONFIG_HOME/protocol-ward/ward.yaml
//  3. /etc/protocolward/ward.yaml
//
// Returns the first path where the file exists, or an error naming all
// searched locations if none are found. If --config was given explicitly, it
// is returned immediately even if the file is absent (Load will produce the
// right typed error with the path named).
func resolveConfigPath(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}

	var candidates []string

	xdgHome := os.Getenv("XDG_CONFIG_HOME")
	if xdgHome == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			xdgHome = home + "/.config"
		}
	}
	if xdgHome != "" {
		candidates = append(candidates, xdgHome+"/protocol-ward/ward.yaml")
	}
	candidates = append(candidates, "/etc/protocolward/ward.yaml")

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	// Build a human-readable list of searched paths for the remediation.
	searched := ""
	for i, p := range candidates {
		if i > 0 {
			searched += ", "
		}
		searched += p
	}
	return "", &serveError{
		Code:        2,
		Message:     fmt.Sprintf("no config file found; searched: %s", searched),
		Remediation: fmt.Sprintf("create ward.yaml at one of the searched paths or pass --config PATH; see ward.example.yaml for a template"),
	}
}

// newServeClassifier builds the slow-path classifier from cfg.Model. It
// returns a nil classifier when no model is configured or a command model
// fails to start (startFailed is then true and ward runs fast-path-only).
// closeFn is never nil; it reaps the model child, if any.
func newServeClassifier(cfg config.Config) (c dataplane.SlowPathClassifier, closeFn func(), startFailed bool) {
	// Per SP10b Ralph F1 + the adapter's `New` docstring: pass
	// context.Background(), NOT serveCtx. The adapter's lifetime is owned by
	// `Close`; ctx cancellation in exec.CommandContext SIGKILLs the child,
	// bypassing the stdin-EOF graceful shutdown path. SIGTERM → ctx.Done()
	// → srv.Shutdown drains in-flight Classify calls (via the dataplane
	// inFlight WaitGroup) → adapter.Close reaps the child cleanly.
	var adapterToClose *model.Adapter
	switch {
	case cfg.Model == nil:
		// No model: stanza — fast-path-only.
	case cfg.Model.Builtin == config.ModelBuiltinLexical:
		// In-process detector: no sibling, nothing to close, no
		// ErrUnavailable latch. Flag-only (ADR-0006).
		c = detect.New()
		slog.Info("policy: model loaded",
			"builtin", cfg.Model.Builtin,
			"mode", "flag-only",
		)
	default:
		ad, mErr := model.New(context.Background(), model.Config{
			Command: cfg.Model.Command,
			Env:     cfg.Model.Env,
		})
		if mErr != nil {
			startFailed = true
			// Continue with nil classifier — ward runs fast-path-only.
			// Single canonical `policy: model unavailable` slog line so
			// operators see one event, not two (Ralph N3). stderr still
			// gets the lipgloss-styled startup line for human eyes; the
			// slog stream gets the canonical msg.
			msg := fmt.Sprintf("policy: model unavailable: %v", mErr)
			rem := "fix model.command in ward.yaml, or remove the model: stanza to run fast-path-only"
			fmt.Fprintln(os.Stderr, styleLabel.Render("model error"))
			fmt.Fprintln(os.Stderr, stylePlain.Render(msg))
			fmt.Fprintln(os.Stderr, styleRemediation.Render("remediation: "+rem))
			slog.Warn("policy: model unavailable",
				"error", mErr.Error(),
				"remediation", rem,
			)
		} else {
			c = ad
			adapterToClose = ad
			slog.Info("policy: model loaded",
				"command", cfg.Model.Command[0],
				"argc", len(cfg.Model.Command),
			)
		}
	}
	closeFn = func() {
		if adapterToClose != nil {
			if cErr := adapterToClose.Close(); cErr != nil {
				// Per Adapter.Close docstring: a non-nil error here is the
				// normal shutdown signature (poison or SIGKILL), not
				// actionable. Debug-level so it doesn't alarm operators.
				slog.Debug("policy: model close (non-fatal)", "error", cErr.Error())
			}
		}
	}
	return c, closeFn, startFailed
}

// startDashboard builds the dashboard handler, binds addr, serves in a
// goroutine and logs dashboard: ready with the bound address. On a bind
// failure it prints the startup error and returns a *serveError (Code 1).
func startDashboard(addr string, store *web.Store, flags *web.FlagLog, srv *dataplane.Server, modelStartFailed bool) (*http.Server, error) {
	dashSrv := &http.Server{
		Addr: addr,
		Handler: web.HandlerWithOptions(store, web.Options{
			Flags:           flags,
			ClassifyDropped: srv.ClassifyDropped,
			Classifier: func() string {
				// A model that failed to start leaves classification off until
				// ward restarts: report unavailable, not none. Checked first.
				if modelStartFailed {
					return dataplane.ClassifierStateUnavailable
				}
				return srv.ClassifierState()
			},
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	dashListener, err := dashListen(addr)
	if err != nil {
		msg := fmt.Sprintf("dashboard listen failed: %v", err)
		rem := "verify nothing else is using " + addr + ", or pass --dash-listen-addr with another loopback address"
		printStartupError("dashboard error", msg, rem)
		return nil, &serveError{Code: 1, Message: msg, Remediation: rem}
	}
	go func() {
		if err := dashSrv.Serve(dashListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("dashboard: serve error",
				"error", err.Error(),
				"remediation", "check the dashboard listener; this is unexpected",
			)
		}
	}()
	slog.Info("dashboard: ready", "listen", dashListener.Addr().String())
	return dashSrv, nil
}

// loadServeConfig resolves the config path, loads and validates the config and
// applies the --listen-addr override. It returns an untyped nil or a
// *serveError (Code 2), printing the startup error before it returns.
func loadServeConfig(opts serveOpts) (config.Config, error) {
	// ── Step 1: Resolve config path ──────────────────────────────────────────
	cfgPath, err := resolveConfigPath(opts.configPath)
	if err != nil {
		var se *serveError
		if errors.As(err, &se) {
			printStartupError("config error", se.Message, se.Remediation)
			return config.Config{}, se
		}
		printStartupError("config error", err.Error(), "")
		return config.Config{}, &serveError{Code: 2, Message: err.Error()}
	}

	// ── Step 2: Load + validate config ───────────────────────────────────────
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return config.Config{}, mapConfigLoadError(cfgPath, err)
	}
	// The flag is validated here, not in internal/config, because it allows
	// port 0 while ward.yaml's listen: must keep rejecting it. It runs before
	// anything binds.
	if opts.listenAddr != "" {
		if err := validateListenFlag(opts.listenAddr); err != nil {
			msg := fmt.Sprintf("invalid --listen-addr %q: %v", opts.listenAddr, err)
			rem := "pass --listen-addr as host:port with a port from 0 to 65535, for example 127.0.0.1:5354 (port 0 lets the kernel pick)"
			printStartupError("config error", msg, rem)
			return config.Config{}, &serveError{Code: 2, Message: msg, Remediation: rem}
		}
		cfg.Listen = opts.listenAddr
	}
	return cfg, nil
}

// newUpstreamClients constructs one upstream client per configured upstream,
// in order, and logs the upstream count. The first failure prints the startup
// error and returns a *serveError (Code 1).
func newUpstreamClients(cfg config.Config) ([]dataplane.Resolver, error) {
	clients := make([]dataplane.Resolver, 0, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		upCfg := upstream.Config{
			Address:     u.Address,
			ServerName:  u.ServerName,
			DialTimeout: cfg.Timeouts.Dial,
			TLSConfig:   buildUpstreamTLSConfig(u),
		}
		c, err := upstream.New(upCfg)
		if err != nil {
			msg := fmt.Sprintf("upstream %q construction failed: %v", u.Address, err)
			rem := fmt.Sprintf("check the address and server_name for upstream %q in ward.yaml", u.Address)
			printStartupError("upstream error", msg, rem)
			return nil, &serveError{Code: 1, Message: msg, Remediation: rem}
		}
		clients = append(clients, c)
	}

	// Name the upstream count so
	// single-unreachable-upstream behavior is auditable.
	slog.Info("ward serve: starting with N upstreams; queries will SERVFAIL if all are unreachable",
		"upstreams", len(clients),
	)
	return clients, nil
}

// loadHostLists compiles the configured blocklists and allowlists. An
// unconfigured list is returned as a nil policy.Matcher interface: block and
// allow are assigned only inside their len(...) > 0 branches, so a nil
// *hostlist.Set never ends up in a non-nil interface. A load failure prints
// the startup error and returns a *serveError (Code 1).
func loadHostLists(cfg config.Config) (allow, block policy.Matcher, err error) {
	if len(cfg.Blocklists) == 0 && len(cfg.Allowlists) == 0 {
		slog.Info("policy: not configured — running as pure DNS forwarder",
			"remediation", "add a blocklists: or allowlists: section to ward.yaml to enable policy",
		)
	} else {
		if len(cfg.Blocklists) > 0 {
			set, stats, err := hostlist.Load(cfg.Blocklists)
			if err != nil {
				msg := fmt.Sprintf("blocklist load failed: %v", err)
				rem := "check blocklists[*].path values in ward.yaml; see ward.example.yaml for a template"
				printStartupError("blocklist error", msg, rem)
				return nil, nil, &serveError{Code: 1, Message: msg, Remediation: rem}
			}
			logListSourceStats(stats)
			slog.Info("blocklist: ready",
				"sources", len(stats),
				"total_entries", totalEntries(stats),
			)
			block = set
		}
		if len(cfg.Allowlists) > 0 {
			set, stats, err := allowlist.Load(cfg.Allowlists)
			if err != nil {
				msg := fmt.Sprintf("allowlist load failed: %v", err)
				rem := "check allowlists[*].path values in ward.yaml; see ward.example.yaml for a template"
				printStartupError("allowlist error", msg, rem)
				return nil, nil, &serveError{Code: 1, Message: msg, Remediation: rem}
			}
			logListSourceStats(stats)
			slog.Info("allowlist: ready",
				"sources", len(stats),
				"total_entries", totalEntries(stats),
			)
			allow = set
		}
		// engineReadyBanner emission deferred until after decoy load so the
		// banner can include decoys_loaded in a single line.
	}
	return allow, block, nil
}

// loadDecoys compiles the configured decoy sources. With none configured it
// returns nil, 0, nil. A load failure prints the startup error and returns a
// *serveError (Code 1). total is the entry count across all sources.
func loadDecoys(cfg config.Config) (decoys *decoy.Set, total int, err error) {
	if len(cfg.Decoys) > 0 {
		set, stats, err := decoy.New(cfg.Decoys)
		if err != nil {
			msg := fmt.Sprintf("decoy load failed: %v", err)
			rem := "check decoys[*].path values in ward.yaml"
			printStartupError("decoy error", msg, rem)
			return nil, 0, &serveError{Code: 1, Message: msg, Remediation: rem}
		}
		for _, st := range stats {
			slog.Info("decoy: loaded source",
				"id", st.ID,
				"path", st.Path,
				"entries", st.Entries,
				"skipped_lines", st.SkippedLines,
				"load_duration_ms", st.LoadDuration.Milliseconds(),
			)
			total += st.Entries
		}
		slog.Info("decoy: ready",
			"sources", len(stats),
			"total_entries", total,
		)
		decoys = set
	}
	return decoys, total, nil
}

// loadServePolicy loads the host lists, builds the policy engine, loads the
// decoys and then emits the engine-ready banner so it can carry decoys_loaded.
// A list error returns before any decoy loads. The engine is always non-nil on
// success: with nil allow and block it forwards everything.
func loadServePolicy(cfg config.Config) (*policy.Engine, *decoy.Set, error) {
	allowSet, blockSet, err := loadHostLists(cfg)
	if err != nil {
		return nil, nil, err
	}

	// The engine is always non-nil; with nil allow and block it forwards everything.
	engine := policy.NewEngine(allowSet, blockSet)

	// Compile decoys (if any).
	decoySet, totalDecoys, err := loadDecoys(cfg)
	if err != nil {
		return nil, nil, err
	}
	// Emit the engine ready banner now that decoys are loaded so the line
	// can carry decoys_loaded alongside the policy mode + block-response shape.
	if allowSet != nil || blockSet != nil {
		logEngineReadyBanner(allowSet, blockSet, cfg.BlockResponse, totalDecoys)
	}
	return engine, decoySet, nil
}

// serveDashAddr resolves the dashboard bind address (default when unset) and
// enforces the loopback-only rule of invariant 4. Callers must run it before
// binding anything. A rejected address prints the startup error and returns a
// *serveError (Code 1).
func serveDashAddr(opts serveOpts) (string, error) {
	dashAddr := opts.dashListenAddr
	if dashAddr == "" {
		dashAddr = dashboardListenAddr
	}
	if err := requireLoopbackDashAddr(dashAddr); err != nil {
		msg := err.Error()
		rem := "bind 127.0.0.1, ::1, or localhost only; non-loopback dashboard bind requires a separate invariant 4 re-review (see internal/web package doc)"
		printStartupError("dashboard error", msg, rem)
		return "", &serveError{Code: 1, Message: msg, Remediation: rem}
	}
	return dashAddr, nil
}

// newServeDataplane constructs the dataplane server from dpCfg using
// opts.newDataplane (dataplane.NewServer when nil). A failure, including a
// constructor that returns no server, prints the startup error and returns a
// *serveError (Code 1) whose remediation comes from bindErrRemediationFor (or
// a report-a-bug note when the constructor returns no server).
func newServeDataplane(opts serveOpts, dpCfg dataplane.Config) (*dataplane.Server, error) {
	newDP := opts.newDataplane
	if newDP == nil {
		newDP = dataplane.NewServer
	}
	srv, err := newDP(dpCfg)
	nilServer := err == nil && srv == nil
	if nilServer {
		err = errors.New("newDataplane returned a nil server")
	}
	if err != nil {
		msg := fmt.Sprintf("dataplane init failed: %v", err)
		rem := "internal error: the dataplane constructor returned no server; report this as a bug"
		if !nilServer {
			rem = bindErrRemediationFor(err, dpCfg.ListenAddr, opts.listenAddr != "")
		}
		printStartupError("startup error", msg, rem)
		return nil, &serveError{Code: 1, Message: msg, Remediation: rem}
	}
	return srv, nil
}

// serveRun is the testable core of the serve subcommand. It returns a
// *serveError on error (Code 1 or 2). A nil return means clean exit.
func serveRun(ctx context.Context, opts serveOpts) error {
	// ── Steps 1-2: Resolve, load and validate config ─────────────────────────
	cfg, err := loadServeConfig(opts)
	if err != nil {
		return err
	}

	// ── Step 3: Bootstrap structured logging ─────────────────────────────────
	slog.SetDefault(obs.NewLogger(cfg.LogLevel))

	// ── Step 4: Construct upstream clients ───────────────────────────────────
	clients, err := newUpstreamClients(cfg)
	if err != nil {
		return err
	}

	// ── Steps 4b-4c: Compile lists and decoys, build the policy engine ───────
	engine, decoySet, err := loadServePolicy(cfg)
	if err != nil {
		return err
	}

	// ── Step 4d: Dashboard store, flag log and loopback check ───────────────
	// The store is constructed before the dataplane so we can pass it as the
	// DecisionRecorder. Loopback-only bind is load-bearing per invariant 4
	// corollary (internal/web package doc); the check runs before any bind.
	dashAddr, err := serveDashAddr(opts)
	if err != nil {
		return err
	}
	dashStore := web.NewStore()
	// flagLog is the dataplane's FlagRecorder and the dashboard's Flags
	// panel source (flag-only — never enforced).
	flagLog := web.NewFlagLog()

	// ── Step 4e: Construct slow-path adapter (if cfg.Model present) ──────────
	classifier, closeClassifier, modelStartFailed := newServeClassifier(cfg)
	hatch := newExitHatch(opts.notifySignals, opts.exit)
	defer hatch.disarm()
	// Deferred so every return path reaps the child after any srv.Shutdown has drained classifyAsync (Risk #2).
	// The hatch is disarmed after the reap: while its budget (timeouts.shutdown + 2s from the first
	// signal) lasts, a second signal during the reap still exits 130 (the exit skips the defers).
	defer closeClassifier()

	// ── Step 5: Construct dataplane server ───────────────────────────────────
	srv, err := newServeDataplane(opts, dataplane.Config{
		ListenAddr:      cfg.Listen,
		Resolvers:       clients,
		Engine:          engine,
		Decoys:          decoySet,
		Decisions:       dashStore,
		Flags:           flagLog,
		BlockResponse:   cfg.BlockResponse,
		CounterSeed:     0,
		QueryTimeout:    cfg.Timeouts.Query,
		ShutdownTimeout: cfg.Timeouts.Shutdown,
		Classifier:      classifier,
	})
	if err != nil {
		// Adapter cleanup runs via the deferred close above.
		return err
	}

	// ── Step 5b: Start the dashboard ─────────────────────────────────────────
	// Only now, so /healthz can read the server and the model state from its
	// first answer. NewServer binds nothing, so a listen failure here needs no
	// dataplane cleanup.
	dashSrv, err := startDashboard(dashAddr, dashStore, flagLog, srv, modelStartFailed)
	if err != nil {
		return err
	}
	defer func() { _ = dashSrv.Close() }()

	// ── Steps 6-8: Serve, wait for a signal or a listener exit, shut down ─────
	return serveUntilStopped(ctx, srv, dashSrv, hatch, cfg, opts.listenAddr != "")
}

// serveUntilStopped serves until the listener exits or ctx is cancelled. On a
// listener exit it closes the dashboard and returns an untyped nil or a
// *serveError (Code 1). On cancel it arms the second-signal hatch, logs the
// drain, runs shutdownServe and returns nil. fromFlag says the listen address
// came from --listen-addr.
func serveUntilStopped(ctx context.Context, srv *dataplane.Server, dash dashServer, hatch *exitHatch, cfg config.Config, fromFlag bool) error {
	// ── Step 6: Start serving (unblocks when shutdown completes) ─────────────
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve()
	}()

	// ── Step 7: Wait for signal or context cancel ─────────────────────────────
	// Rely solely on ctx for signal delivery. In production, ctx comes from
	// signal.NotifyContext (in newServeCmd), which handles SIGINT/SIGTERM.
	// Tests inject cancellation directly via context cancel. A single
	// registration point eliminates the double-registration race where a
	// SIGTERM arriving via ctx.Done() bypassed the escape-hatch goroutine.

	select {
	case <-ctx.Done():
		// Context cancelled — arm the second-signal escape hatch NOW so that a
		// second SIGINT/SIGTERM during the drain budget forces an immediate exit.
		hatch.arm(cfg.Timeouts.Shutdown+2*time.Second, dash)
	case err := <-serveErr:
		// The dataplane has already stopped both DNS listeners and drained
		// in-flight queries. Close the dashboard too, so an early exit
		// (e.g. the DNS port is taken) leaves no listener behind.
		_ = dash.Close()
		if err != nil {
			msg := fmt.Sprintf("listener error: %v", err)
			rem := bindErrRemediationFor(err, cfg.Listen, fromFlag)
			printStartupError("startup error", msg, rem)
			return &serveError{Code: 1, Message: msg, Remediation: rem}
		}
		return nil
	}

	slog.Info("ward serve: shutdown signal received; draining in-flight queries",
		"shutdown_budget", cfg.Timeouts.Shutdown.String(),
	)

	shutdownServe(srv, dash, serveErr, cfg.Timeouts.Shutdown)
	return nil
}

// dashServer is the part of *http.Server the shutdown steps use.
type dashServer interface {
	Close() error
	Shutdown(context.Context) error
}

// shutdownServe is the graceful shutdown: the dashboard first (1 s), then
// the dataplane drain within budget, then a bounded wait for Serve to return.
func shutdownServe(srv *dataplane.Server, dash dashServer, serveErr <-chan error, budget time.Duration) {
	// ── Step 8: Graceful shutdown ─────────────────────────────────────────────
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), budget)
	defer shutdownCancel()

	// Shut the dashboard down first — it's bounded by ReadHeaderTimeout and
	// has no long-running handlers; do this before the DNS drain so a stuck
	// healthz probe can't block the listener close.
	dashShutdownCtx, dashCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer dashCancel()
	if err := dash.Shutdown(dashShutdownCtx); err != nil {
		slog.Warn("dashboard: shutdown error", "error", err.Error())
	}

	if err := srv.Shutdown(shutdownCtx); err != nil {
		if errors.Is(err, dataplane.ErrDrainTimeout) || shutdownCtx.Err() != nil {
			slog.Warn("ward serve: shutdown drain budget elapsed; forcing close",
				"error", err.Error(),
				"remediation", "in-flight queries or classifications were still running when timeouts.shutdown ran out; the error counts the classifications (0 means a query, not the classifier, was stuck); raise timeouts.shutdown in ward.yaml if this recurs",
			)
		} else if containsAny(err.Error(), "server not started") {
			// miekg returns "server not started" if Shutdown races the startup path.
			// This is harmless — the server never fully started so there is nothing
			// to drain. Log at DEBUG so it doesn't alarm operators.
			slog.Debug("ward serve: shutdown called before server fully started; nothing to drain")
		} else {
			slog.Error("ward serve: shutdown error",
				"error", err.Error(),
				"remediation", "check for listener errors in the log above",
			)
		}
	}

	// Drain the serveErr channel so the goroutine exits cleanly.
	select {
	case <-serveErr:
	case <-time.After(500 * time.Millisecond):
	}

	slog.Info("ward serve: stopped")
}

// buildUpstreamTLSConfig returns a *tls.Config that pins the upstream to the
// caller-supplied CA bundle (parsed by config.Load and exposed via
// u.RootCAs), or nil to fall back to system roots when no ca_bundle: is set.
// Extracted from serveRun so the wiring is unit-testable (Ralph F2).
func buildUpstreamTLSConfig(u config.Upstream) *tls.Config {
	if u.RootCAs == nil {
		return nil
	}
	return &tls.Config{
		ServerName: u.ServerName,
		MinVersion: tls.VersionTLS12,
		RootCAs:    u.RootCAs,
	}
}

// validateListenFlag checks a --listen-addr value: host:port with a decimal
// port in 0-65535 (ParseUint rejects signs and service names).
func validateListenFlag(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("port %q is not a number from 0 to 65535", port)
	}
	return nil
}

// bindErrRemediation returns a remediation hint appropriate for the given
// error and listen address (as set in ward.yaml). Specialises on ":53"
// permission-denied to name the setcap recipe.
func bindErrRemediation(err error, listenAddr string) string {
	return bindErrRemediationFor(err, listenAddr, false)
}

// bindErrRemediationFor is bindErrRemediation with the source of the address
// made explicit: when fromFlag is true the address came from --listen-addr, so
// the hint names that flag instead of ward.yaml.
func bindErrRemediationFor(err error, listenAddr string, fromFlag bool) string {
	if errors.Is(err, dataplane.ErrListenerStopped) {
		return "the DNS listener stopped unexpectedly; check the log above and restart ward"
	}
	errStr := err.Error()
	if containsAny(errStr, "permission denied", "operation not permitted") {
		_, port, _ := splitHostPort(listenAddr)
		if port == "53" || port == "853" {
			if fromFlag {
				return fmt.Sprintf("bind to %s requires CAP_NET_BIND_SERVICE; run `sudo setcap cap_net_bind_service=+ep ./bin/ward` or pass --listen-addr with a port >= 1024", listenAddr)
			}
			return fmt.Sprintf("bind to %s requires CAP_NET_BIND_SERVICE; run `sudo setcap cap_net_bind_service=+ep ./bin/ward` or set listen to a port >= 1024 in ward.yaml", listenAddr)
		}
		if n, perr := strconv.Atoi(port); perr == nil && n >= 1024 {
			// The port is already unprivileged, so "use a port >= 1024" is
			// advice the operator has followed; name what else can block it.
			if fromFlag {
				return fmt.Sprintf("bind to %s was refused; check sandbox or firewall rules, or pass --listen-addr with a different address", listenAddr)
			}
			return fmt.Sprintf("bind to %s was refused; check sandbox or firewall rules, or change listen in ward.yaml", listenAddr)
		}
		if fromFlag {
			return fmt.Sprintf("bind to %s was refused; ensure ward has permission or pass --listen-addr with a port >= 1024", listenAddr)
		}
		return fmt.Sprintf("bind to %s was refused; ensure ward has permission or use a port >= 1024", listenAddr)
	}
	if containsAny(errStr, "address already in use", "bind: address already in use") {
		if fromFlag {
			return fmt.Sprintf("port already in use at %s; stop the process using that port or change --listen-addr", listenAddr)
		}
		return fmt.Sprintf("port already in use at %s; stop the process using that port or change listen in ward.yaml", listenAddr)
	}
	if fromFlag {
		return "check the --listen-addr address and port availability"
	}
	return "check listen address and port availability in ward.yaml"
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func splitHostPort(addr string) (host, port string, err error) {
	// Simple wrapper; errors are non-fatal here (remediation fallback handles it).
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return addr, "", fmt.Errorf("no colon in address")
}

// logListSourceStats emits one INFO line per source. The "hostlist:" prefix
// is neutral; the kind-specific summary line ("blocklist: ready" or
// "allowlist: ready") is emitted by the caller.
func logListSourceStats(stats []hostlist.Stats) {
	for _, st := range stats {
		slog.Info("hostlist: loaded source",
			"id", st.ID,
			"path", st.Path,
			"entries", st.Entries,
			"skipped_lines", st.SkippedLines,
			"load_duration_ms", st.LoadDuration.Milliseconds(),
		)
	}
}

func totalEntries(stats []hostlist.Stats) int {
	n := 0
	for _, st := range stats {
		n += st.Entries
	}
	return n
}

// logEngineReadyBanner emits the "policy: engine ready" line.
// mode and block-response fields communicate the engine shape in one line.
// decoysLoaded, when non-zero, surfaces the decoy entry count in the same
// banner so operators see all hostname-classification surfaces at a glance
// (decoy-tripwire T8 Ralph I1).
func logEngineReadyBanner(allow, block policy.Matcher, br config.BlockResponseConfig, decoysLoaded int) {
	var mode string
	switch {
	case allow != nil && block != nil:
		mode = "allowlist+blocklist"
	case allow != nil:
		mode = "allowlist-only"
	case block != nil:
		mode = "blocklist-only"
	default:
		return // pure-forwarder banner already emitted by caller
	}
	attrs := []any{"mode", mode, "block_response_mode", string(br.Mode)}
	if br.Mode == config.BlockResponseModeAddress {
		attrs = append(attrs,
			"block_response_a", br.A.String(),
			"block_response_aaaa", br.AAAA.String(),
		)
	}
	if decoysLoaded > 0 {
		attrs = append(attrs, "decoys_loaded", decoysLoaded)
	}
	slog.Info("policy: engine ready", attrs...)
}

// newServeCmd builds the cobra command for `ward serve`.
func newServeCmd() *cobra.Command {
	var opts serveOpts

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the ward DNS forwarder daemon",
		Long: `ward serve starts the DNS-over-TLS forwarding daemon.

It listens for DNS queries on the configured address and forwards them to
the configured upstream resolvers over DNS-over-TLS (DoT).

Config file is located per the following search order:
  1. --config flag
  2. $XDG_CONFIG_HOME/protocol-ward/ward.yaml
  3. /etc/protocolward/ward.yaml`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			if err := serveRun(ctx, opts); err != nil {
				var se *serveError
				if errors.As(err, &se) {
					os.Exit(se.Code)
				}
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.configPath, "config", "", "path to ward.yaml config file")
	cmd.Flags().StringVar(&opts.dashListenAddr, "dash-listen-addr", "", "override the dashboard bind (default 127.0.0.1:18987; a dashboard config option is planned). Must bind loopback (127.0.0.1, ::1, or localhost); non-loopback requires invariant 4 re-review (see internal/web package doc)")
	cmd.Flags().StringVar(&opts.listenAddr, "listen-addr", "", "override listen: from ward.yaml for ward serve only (ward.yaml must still contain a valid listen:; ward doctor still probes listen:). Port 0 lets the kernel pick; the bound address is logged in dns: listening")
	return cmd
}
