// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"protocolward.ai/ward/internal/update"
)

type updateVerifyOpts struct {
	trustRoot string
}

// updateVerifyRun is the testable core for `ward update verify <fixtureDir>`.
// Returns nil on a holding trust chain, a *serveError otherwise.
//
// Exit-code mapping (mirrors ward serve / ward doctor):
//   - nil          → exit 0
//   - Code 1       → chain broken at one of the verify steps
//   - Code 2       → bad usage (missing/extra args, fixture dir not a directory)
//
// Invariant 8: every failure prints a one-line remediation derived from
// the sentinel that broke the chain.
func updateVerifyRun(out io.Writer, args []string, opts updateVerifyOpts) error {
	if len(args) != 1 {
		return &serveError{
			Code:        2,
			Message:     "usage: ward update verify <fixture-dir> [--trust-root <path>]",
			Remediation: "pass the directory containing root.json, targets.json, and cosign artifacts",
		}
	}
	fixtureDir := args[0]
	info, err := os.Stat(fixtureDir)
	if err != nil {
		return &serveError{
			Code:        2,
			Message:     fmt.Sprintf("fixture dir %q: %v", fixtureDir, err),
			Remediation: "check the path and try again",
		}
	}
	if !info.IsDir() {
		return &serveError{
			Code:        2,
			Message:     fmt.Sprintf("fixture path %q is not a directory", fixtureDir),
			Remediation: "pass the directory itself, not a file inside it",
		}
	}

	vt, err := update.Verify(fixtureDir, opts.trustRoot)
	if err != nil {
		return &serveError{
			Code:        1,
			Message:     err.Error(),
			Remediation: updateRemediation(err),
		}
	}

	expires := vt.Expires.UTC().Format(time.RFC3339)
	_, _ = fmt.Fprintf(out,
		"OK — verified %d target(s); root v%d, targets v%d, expires %s\n",
		len(vt.Targets), vt.RootVersion, vt.TargetsVersion, expires)
	return nil
}

// updateRemediation maps a verify-step sentinel to a one-line remediation.
// Returns the empty string for unknown errors (caller falls back to a
// generic message via serveError.Remediation).
func updateRemediation(err error) string {
	switch {
	case errors.Is(err, update.ErrFixtureLayout):
		return "check the fixture directory layout: root.json, root.json.cosign-bundle, cosign-trust-root.pem, targets.json, and a targets/ directory must all exist"
	case errors.Is(err, update.ErrCosignBundle):
		return "regenerate the cosign bundle (cosign sign-blob) or verify the trust root matches the bundle's issuer"
	case errors.Is(err, update.ErrTUFRoot):
		return "the TUF root metadata is corrupted or signed by an untrusted key; re-fetch root.json from the update channel"
	case errors.Is(err, update.ErrTUFTargets):
		return "the TUF targets metadata is invalid or expired; pull a fresh targets.json from the update channel"
	case errors.Is(err, update.ErrTargetHash):
		return "a target file's on-disk bytes do not match its TUF-declared sha256; re-fetch the target"
	default:
		return "see the wrapped error above"
	}
}

func newUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Operate on the signed update channel (verify metadata fixtures today)",
		Long: `ward update is the parent for signed-update-channel subcommands.

Today only ` + "`update verify`" + ` ships, the metadata verifier;
` + "`update fetch`" + ` and ` + "`update apply`" + ` are planned.

The verifier walks a two-layer trust chain: cosign-over-TUF-root, then
TUF root → targets, then per-target hash check. No network is contacted.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newUpdateVerifyCmd())
	return cmd
}

func newUpdateVerifyCmd() *cobra.Command {
	var opts updateVerifyOpts
	cmd := &cobra.Command{
		Use:   "verify <fixture-dir>",
		Short: "Verify a cosign-signed TUF metadata fixture (no network)",
		Long: `ward update verify validates a local on-disk fixture against a
two-layer trust chain. Exits 0 only when every step passes.

Fixture layout (each path relative to <fixture-dir>):
  root.json                   TUF root metadata
  root.json.cosign-bundle     cosign-signed envelope over root.json
  cosign-trust-root.pem       pinned issuer cert
  targets.json                TUF targets metadata
  targets/<name>              every file referenced by targets.json

Exit codes:
  0   chain holds
  1   chain broken (the printed error names the broken link)
  2   bad usage`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := updateVerifyRun(cmd.OutOrStdout(), args, opts); err != nil {
				var se *serveError
				if errors.As(err, &se) {
					printStartupError("update verify", se.Message, se.Remediation)
					os.Exit(se.Code)
				}
				printStartupError("update verify", err.Error(), "")
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.trustRoot, "trust-root", "",
		"path to the pinned cosign trust-root cert (PEM); defaults to <fixture-dir>/cosign-trust-root.pem")
	return cmd
}
