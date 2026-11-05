// SPDX-License-Identifier: Apache-2.0

package obs_test

import (
	"bytes"
	"log"
	"log/slog"
	"testing"

	"protocolward.ai/ward/internal/obs"
)

func TestCountRecords_CountsMatchingMessageBySourceID(t *testing.T) {
	c := obs.CountRecords(t, "target")
	slog.Warn("target", "source_id", "a")
	slog.Warn("target", "source_id", "a")
	slog.Warn("target", "source_id", "b")
	slog.Warn("other", "source_id", "a")
	if got := c.Take("a"); got != 2 {
		t.Fatalf("Take(a) = %d, want 2", got)
	}
	if got := c.Take("b"); got != 1 {
		t.Fatalf("Take(b) = %d, want 1", got)
	}
}

func TestCountRecords_RecordWithoutSourceIDNotCounted(t *testing.T) {
	c := obs.CountRecords(t, "target")
	slog.Warn("target", "other_key", "a")
	slog.Warn("target")
	if got := c.Take(""); got != 0 {
		t.Fatalf("Take(\"\") = %d, want 0", got)
	}
	if got := c.Take("a"); got != 0 {
		t.Fatalf("Take(a) = %d, want 0", got)
	}
}

func TestCountRecords_TakeClears(t *testing.T) {
	c := obs.CountRecords(t, "target")
	slog.Warn("target", "source_id", "a")
	if got := c.Take("a"); got != 1 {
		t.Fatalf("first Take = %d, want 1", got)
	}
	if got := c.Take("a"); got != 0 {
		t.Fatalf("second Take = %d, want 0", got)
	}
}

func TestRecordCounter_ZeroValueDoesNotPanic(t *testing.T) {
	var c obs.RecordCounter
	slog.New(&c).Warn("anything", "source_id", "a")
	if got := c.Take("a"); got != 0 {
		t.Fatalf("zero-value Take = %d, want 0", got)
	}
}

func TestCountRecords_CleanupRestoresLoggingState(t *testing.T) {
	origWriter, origFlags := log.Writer(), log.Flags()
	t.Cleanup(func() {
		log.SetOutput(origWriter)
		log.SetFlags(origFlags)
	})
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(log.Lshortfile)
	prevDefault := slog.Default()

	t.Run("install", func(t *testing.T) {
		obs.CountRecords(t, "target")
		if slog.Default() == prevDefault {
			t.Fatal("CountRecords did not install a default logger")
		}
	})

	if slog.Default() != prevDefault {
		t.Fatal("slog default not restored after cleanup")
	}
	if log.Flags() != log.Lshortfile {
		t.Fatalf("log flags = %d, want %d", log.Flags(), log.Lshortfile)
	}
	if log.Writer() != &buf {
		t.Fatal("log writer not restored after cleanup")
	}
}
