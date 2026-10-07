// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
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
// Fixed today; a dashboard config option (config-file override) is planned. Loopback-only is load-bearing — see internal/web package doc.
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

// serveRun is the testable core of the serve subcommand. It returns a
// *serveError on error (Code 1 or 2). A nil return means clean exit.
func serveRun(ctx context.Context, opts serveOpts) error {
	// ── Step 1: Resolve config path ──────────────────────────────────────────
	cfgPath, err := resolveConfigPath(opts.configPath)
	if err != nil {
		var se *serveError
		if errors.As(err, &se) {
			printStartupError("config error", se.Message, se.Remediation)
			return se
		}
		printStartupError("config error", err.Error(), "")
		return &serveError{Code: 2, Message: err.Error()}
	}

	// ── Step 2: Load + validate config ───────────────────────────────────────
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return mapConfigLoadError(cfgPath, err)
	}

	// ── Step 3: Bootstrap structured logging ─────────────────────────────────
	logger := obs.NewLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	// ── Step 4: Construct upstream clients ───────────────────────────────────
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
			return &serveError{Code: 1, Message: msg, Remediation: rem}
		}
		clients = append(clients, c)
	}

	// Name the upstream count so
	// single-unreachable-upstream behavior is auditable.
	slog.Info("ward serve: starting with N upstreams; queries will SERVFAIL if all are unreachable",
		"upstreams", len(clients),
	)

	// ── Step 4b: Compile blocklists and allowlists (if any) ──────────────────
	var (
		blockSet, allowSet policy.Matcher // policy.Matcher; both may stay nil
	)

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
				return &serveError{Code: 1, Message: msg, Remediation: rem}
			}
			logListSourceStats(stats)
			slog.Info("blocklist: ready",
				"sources", len(stats),
				"total_entries", totalEntries(stats),
			)
			blockSet = set
		}
		if len(cfg.Allowlists) > 0 {
			set, stats, err := allowlist.Load(cfg.Allowlists)
			if err != nil {
				msg := fmt.Sprintf("allowlist load failed: %v", err)
				rem := "check allowlists[*].path values in ward.yaml; see ward.example.yaml for a template"
				printStartupError("allowlist error", msg, rem)
				return &serveError{Code: 1, Message: msg, Remediation: rem}
			}
			logListSourceStats(stats)
			slog.Info("allowlist: ready",
				"sources", len(stats),
				"total_entries", totalEntries(stats),
			)
			allowSet = set
		}
		// engineReadyBanner emission deferred until after decoy load so the
		// banner can include decoys_loaded in a single line.
	}

	// engine may be nil-nil; dataplane respects nil Engine as pure-forwarder.
	engine := policy.NewEngine(allowSet, blockSet)

	// ── Step 4c: Compile decoys (if any) ─────────────────────────────────────
	var decoySet *decoy.Set
	var totalDecoys int
	if len(cfg.Decoys) > 0 {
		set, stats, err := decoy.New(cfg.Decoys)
		if err != nil {
			msg := fmt.Sprintf("decoy load failed: %v", err)
			rem := "check decoys[*].path values in ward.yaml"
			printStartupError("decoy error", msg, rem)
			return &serveError{Code: 1, Message: msg, Remediation: rem}
		}
		for _, st := range stats {
			slog.Info("decoy: loaded source",
				"id", st.ID,
				"path", st.Path,
				"entries", st.Entries,
				"skipped_lines", st.SkippedLines,
				"load_duration_ms", st.LoadDuration.Milliseconds(),
			)
			totalDecoys += st.Entries
		}
		slog.Info("decoy: ready",
			"sources", len(stats),
			"total_entries", totalDecoys,
		)
		decoySet = set
	}
	// Emit the engine ready banner now that decoys are loaded so the line
	// can carry decoys_loaded alongside the policy mode + block-response shape.
	if allowSet != nil || blockSet != nil {
		logEngineReadyBanner(allowSet, blockSet, cfg.BlockResponse, totalDecoys)
	}

	// ── Step 4d: Dashboard last-decision store + HTTP server ────────────────
	// The store is constructed before the dataplane so we can pass it as the
	// DecisionRecorder. Loopback-only bind is load-bearing per invariant 4
	// corollary (internal/web package doc).
	dashAddr := opts.dashListenAddr
	if dashAddr == "" {
		dashAddr = dashboardListenAddr
	}
	if err := requireLoopbackDashAddr(dashAddr); err != nil {
		msg := err.Error()
		rem := "bind 127.0.0.1, ::1, or localhost only; non-loopback dashboard bind requires a separate invariant 4 re-review (see internal/web package doc)"
		printStartupError("dashboard error", msg, rem)
		return &serveError{Code: 1, Message: msg, Remediation: rem}
	}
	dashStore := web.NewStore()
	// flagLog is the dataplane's FlagRecorder and the dashboard's Flags
	// panel source (flag-only — never enforced).
	flagLog := web.NewFlagLog()
	dashSrv := &http.Server{
		Addr:              dashAddr,
		Handler:           web.HandlerWithFlags(dashStore, flagLog),
		ReadHeaderTimeout: 5 * time.Second,
	}
	dashListener, err := dashListen(dashAddr)
	if err != nil {
		msg := fmt.Sprintf("dashboard listen failed: %v", err)
		rem := "verify nothing else is using " + dashAddr + "; the dashboard port is fixed today (a dashboard config option is planned)"
		printStartupError("dashboard error", msg, rem)
		return &serveError{Code: 1, Message: msg, Remediation: rem}
	}
	go func() {
		if err := dashSrv.Serve(dashListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("dashboard: serve error",
				"error", err.Error(),
				"remediation", "check the dashboard listener; this is unexpected",
			)
		}
	}()
	slog.Info("dashboard: ready", "listen", dashAddr)

	// ── Step 4e: Construct slow-path adapter (if cfg.Model present) ──────────
	// Per SP10b Ralph F1 + the adapter's `New` docstring: pass
	// context.Background(), NOT serveCtx. The adapter's lifetime is owned by
	// `Close`; ctx cancellation in exec.CommandContext SIGKILLs the child,
	// bypassing the stdin-EOF graceful shutdown path. SIGTERM → ctx.Done()
	// → srv.Shutdown drains in-flight Classify calls (via the dataplane
	// inFlight WaitGroup) → adapter.Close reaps the child cleanly.
	var classifier dataplane.SlowPathClassifier
	var adapterToClose *model.Adapter
	switch {
	case cfg.Model == nil:
		// No model: stanza — fast-path-only.
	case cfg.Model.Builtin == config.ModelBuiltinLexical:
		// In-process detector: no sibling, nothing to close, no
		// ErrUnavailable latch. Flag-only (ADR-0006).
		classifier = detect.New()
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
			classifier = ad
			adapterToClose = ad
			slog.Info("policy: model loaded",
				"command", cfg.Model.Command[0],
				"argc", len(cfg.Model.Command),
			)
		}
	}
	// Adapter close is deferred here so EVERY return path (including the
	// early serveErr-channel exit at step 7) reaps the child. The defer
	// fires AFTER any inline srv.Shutdown has drained classifyAsync
	// goroutines (Risk #2 mitigation): defers run at function exit, after
	// the inline shutdown completes.
	defer func() {
		if adapterToClose != nil {
			if cErr := adapterToClose.Close(); cErr != nil {
				// Per Adapter.Close docstring: a non-nil error here is the
				// normal shutdown signature (poison or SIGKILL), not
				// actionable. Debug-level so it doesn't alarm operators.
				slog.Debug("policy: model close (non-fatal)", "error", cErr.Error())
			}
		}
	}()

	// ── Step 5: Construct dataplane server ───────────────────────────────────
	srv, err := dataplane.NewServer(dataplane.Config{
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
		msg := fmt.Sprintf("dataplane init failed: %v", err)
		rem := bindErrRemediation(err, cfg.Listen)
		printStartupError("startup error", msg, rem)
		return &serveError{Code: 1, Message: msg, Remediation: rem}
	}

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
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			select {
			case <-sigCh:
				// Second signal during shutdown → immediate exit (130 = 128+SIGINT).
				os.Exit(130)
			case <-time.After(cfg.Timeouts.Shutdown + 2*time.Second):
				// Drain budget elapsed; outer logic handles the forced close.
				signal.Stop(sigCh)
			}
		}()
	case err := <-serveErr:
		if err != nil {
			msg := fmt.Sprintf("listener error: %v", err)
			rem := bindErrRemediation(err, cfg.Listen)
			printStartupError("startup error", msg, rem)
			return &serveError{Code: 1, Message: msg, Remediation: rem}
		}
		return nil
	}

	slog.Info("ward serve: shutdown signal received; draining in-flight queries",
		"shutdown_budget", cfg.Timeouts.Shutdown.String(),
	)

	// ── Step 8: Graceful shutdown ─────────────────────────────────────────────
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Timeouts.Shutdown)
	defer shutdownCancel()

	// Shut the dashboard down first — it's bounded by ReadHeaderTimeout and
	// has no long-running handlers; do this before the DNS drain so a stuck
	// healthz probe can't block the listener close.
	dashShutdownCtx, dashCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer dashCancel()
	if err := dashSrv.Shutdown(dashShutdownCtx); err != nil {
		slog.Warn("dashboard: shutdown error", "error", err.Error())
	}

	if err := srv.Shutdown(shutdownCtx); err != nil {
		if shutdownCtx.Err() != nil {
			slog.Warn("ward serve: shutdown drain budget elapsed; forcing close",
				"error", err.Error(),
				"remediation", "in-flight queries may have been dropped; increase timeouts.shutdown in ward.yaml if this is common",
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
	return nil
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

// bindErrRemediation returns a remediation hint appropriate for the given
// error and listen address. Specialises on ":53" permission-denied to name
// the setcap recipe.
func bindErrRemediation(err error, listenAddr string) string {
	errStr := err.Error()
	if containsAny(errStr, "permission denied", "operation not permitted") {
		_, port, _ := splitHostPort(listenAddr)
		if port == "53" || port == "853" {
			return fmt.Sprintf("bind to %s requires CAP_NET_BIND_SERVICE; run `sudo setcap cap_net_bind_service=+ep ./bin/ward` or set listen to a port >= 1024 in ward.yaml", listenAddr)
		}
		return fmt.Sprintf("bind to %s was refused; ensure ward has permission or use a port >= 1024", listenAddr)
	}
	if containsAny(errStr, "address already in use", "bind: address already in use") {
		return fmt.Sprintf("port already in use at %s; stop the process using that port or change listen in ward.yaml", listenAddr)
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
	return cmd
}
