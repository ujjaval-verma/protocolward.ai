// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"

	"protocolward.ai/ward/internal/config"
	"protocolward.ai/ward/internal/model"
	"protocolward.ai/ward/pkg/detect"
	pmodel "protocolward.ai/ward/pkg/model"
)

// openModelClassifier builds the slow-path classifier a model: stanza names,
// for both ward serve and ward eval. builtin: lexical gives the in-process
// detector (pkg/detect) and a no-op closer. Anything else is a command
// (config validation guarantees exactly one of the two): it spawns the
// sibling adapter, and closeFn reaps it. Every record goes to logger: the
// model-loaded Info line on success, and the Debug line for a non-nil Close
// error, as Adapter.Close asks. ward serve passes slog.Default(), and ward
// eval passes a discard logger, because it prints no log lines. On a spawn
// failure it logs nothing and returns a nil classifier, a no-op closeFn and
// model.New's error unwrapped; the caller decides whether that is fatal and
// how to report it. m and logger must be non-nil: the callers handle a
// missing stanza (eval: exit 2; serve: fast-path-only). closeFn is never nil.
func openModelClassifier(m *config.ModelConfig, logger *slog.Logger) (c pmodel.Classifier, closeFn func(), err error) {
	if m.Builtin == config.ModelBuiltinLexical {
		// In-process detector: no sibling, nothing to close, no
		// ErrUnavailable latch. Flag-only (ADR-0006).
		logger.Info("policy: model loaded",
			"builtin", m.Builtin,
			"mode", "flag-only",
		)
		return detect.New(), func() {}, nil
	}
	// Per SP10b Ralph F1 + the adapter's `New` docstring: pass
	// context.Background(), not the caller's context (serveCtx in ward
	// serve): the adapter's lifetime is owned by Close; ctx cancellation in
	// exec.CommandContext SIGKILLs the child, bypassing the stdin-EOF
	// graceful path. In ward serve, SIGTERM → srv.Shutdown drains in-flight
	// Classify calls → closeFn reaps the child.
	ad, err := model.New(context.Background(), model.Config{
		Command: m.Command,
		Env:     m.Env,
	})
	if err != nil {
		return nil, func() {}, err
	}
	logger.Info("policy: model loaded",
		"command", m.Command[0],
		"argc", len(m.Command),
	)
	return ad, func() {
		if cErr := ad.Close(); cErr != nil {
			// Per Adapter.Close docstring: a non-nil error here is the
			// normal shutdown signature (poison or SIGKILL), not
			// actionable. Debug-level so it doesn't alarm operators.
			logger.Debug("policy: model close (non-fatal)", "error", cErr.Error())
		}
	}, nil
}
