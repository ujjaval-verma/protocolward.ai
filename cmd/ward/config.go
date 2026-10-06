// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"protocolward.ai/ward/internal/config"
)

// configExportOpts holds parsed flags for `ward config export`.
type configExportOpts struct {
	configPath string
}

// configExportRun is the testable core. Reads the config from the resolved
// path, calls config.Export, and writes the YAML to stdout. Returns a
// *serveError so the CLI can map exit codes the same way `ward serve` does:
// 2 for config-resolution / load failures, 1 for unexpected internal errors.
func configExportRun(out io.Writer, opts configExportOpts) error {
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

	data, err := config.Export(cfg)
	if err != nil {
		msg := fmt.Sprintf("config export marshal failed: %v", err)
		rem := "report this as a bug — yaml.Marshal on exportConfig should not fail"
		printStartupError("internal error", msg, rem)
		return &serveError{Code: 1, Message: msg, Remediation: rem}
	}
	if _, err := out.Write(data); err != nil {
		return &serveError{Code: 1, Message: fmt.Sprintf("write export to stdout: %v", err)}
	}
	return nil
}

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "config",
		Short:         "Inspect and export ward configuration",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newConfigExportCmd())
	return cmd
}

func newConfigExportCmd() *cobra.Command {
	var opts configExportOpts
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Print the validated configuration as YAML (decoys redacted per invariant 6)",
		Long: `ward config export reads ward.yaml from the standard search path
(--config, $XDG_CONFIG_HOME/protocol-ward/ward.yaml, /etc/protocolward/ward.yaml),
validates it, and prints the result as YAML on stdout.

Decoy hostnames are NEVER included in the output (per invariant 6: a config
dumped from an instance with decoys configured MUST NOT include decoy
hostnames in exportable / shareable artifacts).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := configExportRun(cmd.OutOrStdout(), opts); err != nil {
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
