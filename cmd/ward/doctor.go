// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"protocolward.ai/ward/internal/config"
)

type doctorOpts struct {
	configPath string
}

// upstreamProbeResult is one row in the doctor report.
type upstreamProbeResult struct {
	Address string
	OK      bool
	Detail  string // error string when !OK; empty otherwise
}

var (
	doctorLabelStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214")) // amber
	doctorOKStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))             // green
	doctorFailStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))            // red
	doctorMutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))            // muted grey
)

// probeBind attempts to briefly bind UDP+TCP on listenAddr. Returns nil if
// both succeed and release cleanly. Failure → the underlying *net.OpError.
func probeBind(listenAddr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", listenAddr, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("udp bind %q: %w", listenAddr, err)
	}
	udpConn.Close()
	tcpListener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("tcp bind %q: %w", listenAddr, err)
	}
	tcpListener.Close()
	return nil
}

// probeUpstream performs a TCP-only reachability check against address with
// the given timeout. Does NOT initiate a TLS handshake (that would couple
// the doctor probe to upstream cert validity, which is out of scope for v0.1).
// Returns an upstreamProbeResult with OK + Detail populated.
func probeUpstream(address string, timeout time.Duration) upstreamProbeResult {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return upstreamProbeResult{Address: address, OK: false, Detail: err.Error()}
	}
	conn.Close()
	return upstreamProbeResult{Address: address, OK: true}
}

// doctorRun is the testable core. Writes the report to out (intended:
// stdout). Returns nil on all-PASS; on any FAIL, returns a non-nil error so
// the cobra layer can exit non-zero. Config-load errors return *serveError
// with Code=2 (same envelope as ward serve / ward config export).
func doctorRun(out io.Writer, opts doctorOpts) error {
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
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return mapConfigLoadError(cfgPath, err)
	}

	fmt.Fprintln(out, doctorLabelStyle.Render("ward doctor"))
	fmt.Fprintln(out, doctorMutedStyle.Render("config: "+cfgPath))
	fmt.Fprintln(out)

	anyFail := false

	// Bind probe.
	if bindErr := probeBind(cfg.Listen); bindErr != nil {
		anyFail = true
		fmt.Fprintln(out, doctorFailStyle.Render("[FAIL]")+" bind "+cfg.Listen)
		fmt.Fprintln(out, doctorMutedStyle.Render("       "+bindErr.Error()))
		fmt.Fprintln(out, doctorMutedStyle.Render("       remediation: "+bindErrRemediation(bindErr, cfg.Listen)))
	} else {
		fmt.Fprintln(out, doctorOKStyle.Render("[OK]  ")+" bind "+cfg.Listen)
	}

	// Upstream probes.
	for _, u := range cfg.Upstreams {
		r := probeUpstream(u.Address, 2*time.Second)
		if r.OK {
			fmt.Fprintln(out, doctorOKStyle.Render("[OK]  ")+" upstream "+u.Address+" ("+u.ServerName+")")
		} else {
			anyFail = true
			fmt.Fprintln(out, doctorFailStyle.Render("[FAIL]")+" upstream "+u.Address+" ("+u.ServerName+")")
			fmt.Fprintln(out, doctorMutedStyle.Render("       "+r.Detail))
			fmt.Fprintln(out, doctorMutedStyle.Render("       remediation: verify the upstream address in ward.yaml and TCP/853 network egress"))
		}
	}

	if anyFail {
		return &serveError{Code: 1, Message: "one or more probes failed; see report above"}
	}
	return nil
}

func newDoctorCmd() *cobra.Command {
	var opts doctorOpts
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose ward configuration: bind + upstream probes (TCP reachability only — DoT handshake deferred to --deep)",
		Long: `ward doctor runs a one-shot diagnostic against the current configuration.

Two probes:
  - bind: briefly opens UDP+TCP on listen, then releases.
  - upstream: per-upstream TCP three-way handshake to the configured address.

Notes:
  - A passing bind probe is necessary but not sufficient: port availability
    is not guaranteed to persist until 'ward serve' actually starts.
  - The upstream probe is TCP-only; a misconfigured DoT upstream that accepts
    TCP but rejects TLS will still report OK. --deep mode (future) adds the
    TLS handshake.

Exits 0 only if every probe passes.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := doctorRun(cmd.OutOrStdout(), opts); err != nil {
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
	return cmd
}
