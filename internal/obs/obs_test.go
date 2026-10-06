// SPDX-License-Identifier: Apache-2.0

package obs_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/obs"
)

func TestNewLogger_InfoLevel(t *testing.T) {
	logger := obs.NewLogger("info")
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	if !logger.Enabled(context.TODO(), slog.LevelInfo) {
		t.Error("info level not enabled at info")
	}
	if logger.Enabled(context.TODO(), slog.LevelDebug) {
		t.Error("debug level should not be enabled at info")
	}
}

func TestNewLogger_DebugLevel(t *testing.T) {
	logger := obs.NewLogger("debug")
	if !logger.Enabled(context.TODO(), slog.LevelDebug) {
		t.Error("debug level not enabled at debug")
	}
}

func TestNewLogger_WarnLevel(t *testing.T) {
	logger := obs.NewLogger("warn")
	if !logger.Enabled(context.TODO(), slog.LevelWarn) {
		t.Error("warn level not enabled at warn")
	}
	if logger.Enabled(context.TODO(), slog.LevelInfo) {
		t.Error("info level should not be enabled at warn")
	}
}

func TestNewLogger_ErrorLevel(t *testing.T) {
	logger := obs.NewLogger("error")
	if !logger.Enabled(context.TODO(), slog.LevelError) {
		t.Error("error level not enabled at error")
	}
	if logger.Enabled(context.TODO(), slog.LevelWarn) {
		t.Error("warn level should not be enabled at error")
	}
}

func TestNewLogger_UnknownLevelDefaultsToInfo(t *testing.T) {
	logger := obs.NewLogger("garbage")
	if !logger.Enabled(context.TODO(), slog.LevelInfo) {
		t.Error("info level not enabled on unknown level input")
	}
	if logger.Enabled(context.TODO(), slog.LevelDebug) {
		t.Error("debug should not be enabled when unknown level input given")
	}
}

func TestCapture_StructuredRecord(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	slog.Info("hello", "key", "value")

	records := obs.Captured(t)
	if len(records) == 0 {
		t.Fatal("expected at least one captured log record")
	}
	found := false
	for _, r := range records {
		if msg, ok := r["msg"].(string); ok && strings.Contains(msg, "hello") {
			if r["key"] != "value" {
				t.Errorf("expected key=value, got key=%v", r["key"])
			}
			found = true
			break
		}
	}
	if !found {
		t.Errorf("did not find expected log record in %v", records)
	}
}

func TestCapture_RemediationField(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()

	slog.Error("something failed", "remediation", "restart the service")

	records := obs.Captured(t)
	if len(records) == 0 {
		t.Fatal("expected at least one captured log record")
	}
	found := false
	for _, r := range records {
		if rem, ok := r["remediation"].(string); ok && rem == "restart the service" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("remediation field not found in captured records: %v", records)
	}
}

// TestCapture_ParallelSubtests_NoRace verifies that two parallel sub-tests
// can each call obs.Capture + Captured concurrently without racing on the
// package-level capturedBuf map. Run with -race to catch any missing mutex
// protection on the map (capturedMu in capture.go).
//
// This test does NOT assert on the captured record CONTENT — Capture replaces
// slog.Default globally, so two parallel sub-tests' SetDefault calls race
// each other. Records can land in either sub-test's buffer or get lost.
// Per the explicit contract in capture.go: "callers that need strict log
// isolation should avoid combining Capture with t.Parallel at the same level."
// The remaining assertion is that the package-level map operations are safe.
func TestCapture_ParallelSubtests_NoRace(t *testing.T) {
	t.Run("a", func(t *testing.T) {
		t.Parallel()
		restore := obs.Capture(t)
		defer restore()
		for i := 0; i < 10; i++ {
			slog.Info("parallel-a", "i", i)
		}
		_ = obs.Captured(t) // exercises the map + buffer read paths under -race
	})
	t.Run("b", func(t *testing.T) {
		t.Parallel()
		restore := obs.Capture(t)
		defer restore()
		for i := 0; i < 10; i++ {
			slog.Info("parallel-b", "i", i)
		}
		_ = obs.Captured(t)
	})
}
