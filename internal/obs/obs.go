// SPDX-License-Identifier: Apache-2.0

// Package obs bootstraps structured logging for ward and provides an
// extension seam for future metrics/tracing.
package obs

import (
	"log/slog"
	"os"
)

// NewLogger creates a JSON slog.Logger writing to stdout at the given level.
// Unknown level strings default to INFO. This function does NOT replace
// slog.Default(); callers do that explicitly so the replacement is visible.
func NewLogger(level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "info":
		l = slog.LevelInfo
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

// MetricsSeam is the documented extension point for a future /metrics exporter.
// When Prometheus support lands, add a prometheus.Handler here and wire it
// into the serve lifecycle. No other file needs to change.
//
// EXT: compose additional slog.Handler entries here (e.g. OTEL span exporter,
// Prometheus counter handler) before returning from NewLogger.
//
// For now it is intentionally empty; the symbol exists to make the seam
// grep-able in code review.
type MetricsSeam struct{}
