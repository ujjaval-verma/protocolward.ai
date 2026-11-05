// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"context"
	"log"
	"log/slog"
	"sync"
	"testing"
)

// RecordCounter is a slog.Handler that counts records with one message, keyed
// by the string value of their source_id attribute. Records with another
// message, or without a source_id attribute, are ignored. Construct it only
// through CountRecords; the zero value is safe to use but counts nothing
// until it has a message to match.
type RecordCounter struct {
	msg    string
	mu     sync.Mutex
	counts map[string]int
}

// Enabled reports true for every level, so no record is filtered out before
// Handle sees it.
func (c *RecordCounter) Enabled(context.Context, slog.Level) bool { return true }

// Handle counts the record when its message matches and it has a source_id
// attribute (the first one wins).
func (c *RecordCounter) Handle(_ context.Context, r slog.Record) error {
	if r.Message != c.msg {
		return nil
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "source_id" {
			c.mu.Lock()
			if c.counts == nil {
				c.counts = map[string]int{}
			}
			c.counts[a.Value.String()]++
			c.mu.Unlock()
			return false
		}
		return true
	})
	return nil
}

// WithAttrs returns the receiver; attributes added through a derived logger
// are not counted.
func (c *RecordCounter) WithAttrs([]slog.Attr) slog.Handler { return c }

// WithGroup returns the receiver; groups are ignored.
func (c *RecordCounter) WithGroup(string) slog.Handler { return c }

// Take returns the count for one source_id and clears it, so the map does not
// grow while a fuzz target runs.
func (c *RecordCounter) Take(id string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.counts[id]
	delete(c.counts, id)
	return n
}

// CountRecords makes a RecordCounter for msg the default logger and restores
// the previous slog default, log output and log flags on tb's cleanup. With
// the built-in default handler slog.SetDefault redirects the log package, so
// restoring the slog default alone would not undo it.
//
// It is a test helper. Like Capture it swaps the process-wide default, so do
// not combine it with t.Parallel at the same level.
func CountRecords(tb testing.TB, msg string) *RecordCounter {
	tb.Helper()
	c := &RecordCounter{msg: msg, counts: map[string]int{}}
	prev := slog.Default()
	prevWriter, prevFlags := log.Writer(), log.Flags()
	slog.SetDefault(slog.New(c))
	tb.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})
	return c
}
