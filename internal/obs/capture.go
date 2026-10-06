// SPDX-License-Identifier: Apache-2.0

// Capture / Captured / restore lifecycle
//
// Capture installs a buffered JSON slog handler for the duration of one test.
// It is safe to call from sequential tests, parallel sub-tests, and nested
// sub-tests — with the following guarantees:
//
//   - syncBuf (a bytes.Buffer + sync.Mutex) serialises concurrent Write calls
//     from DNS handler goroutines and Read calls from the test goroutine. Each
//     test gets its own syncBuf so no cross-test buffer sharing occurs.
//
//   - capturedMu (a package-level sync.Mutex) guards all reads, writes, and
//     deletes on the capturedBuf map. This is the second mutex and exists
//     independently of syncBuf: syncBuf guards buffer contents; capturedMu
//     guards map membership. Both must be held only in their narrow scope —
//     never both at once — to avoid a lock-order cycle.
//
//   - t.Cleanup registers the restore closure so that even if the test panics
//     or the caller forgets to defer the returned function, slog.Default is
//     always restored before the next test runs. Calling the returned restore
//     function before Cleanup fires is safe: the restored flag prevents a
//     double-restore.
//
//   - Under t.Parallel() with multiple sub-tests, each sub-test holds its own
//     map entry and its own syncBuf. Captures from sibling sub-tests do not
//     interfere. The package-level slog.Default IS shared across goroutines;
//     callers that need strict log isolation should avoid combining Capture with
//     t.Parallel at the same level.
package obs

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
)

// syncBuf is a bytes.Buffer protected by a mutex so that concurrent slog
// writes from DNS handler goroutines and reads from the test goroutine do not
// race. The dataplane tests exercise this pattern: a DNS server goroutine
// calls slog.Info while the test goroutine reads Captured() after the query
// returns but before the handler goroutine has fully exited.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, s.buf.Len())
	copy(cp, s.buf.Bytes())
	return cp
}

// capturedBuf maps test pointers to their capture buffers.
// capturedMu guards all reads, writes, and deletes on capturedBuf. The map
// is no longer safe for concurrent access under t.Parallel(): two sub-tests
// calling Capture concurrently race on the map itself (not the buffer).
// The existing syncBuf.mu continues to guard the buffer contents separately.
var (
	capturedMu  sync.Mutex
	capturedBuf = map[*testing.T]*syncBuf{}
)

// Capture installs a buffered JSON slog handler as slog.Default() and
// returns a restore function the caller should defer. Records are
// retrievable via Captured(t). t.Cleanup also restores slog.Default.
func Capture(t *testing.T) func() {
	t.Helper()
	buf := &syncBuf{}
	h := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	prev := slog.Default()
	slog.SetDefault(slog.New(h))

	capturedMu.Lock()
	capturedBuf[t] = buf
	capturedMu.Unlock()

	restored := false
	restore := func() {
		if !restored {
			restored = true
			capturedMu.Lock()
			delete(capturedBuf, t)
			capturedMu.Unlock()
			slog.SetDefault(prev)
		}
	}
	t.Cleanup(restore)
	return restore
}

// Captured returns all structured log records emitted since Capture was called.
// Each record is a map[string]any decoded from the JSON handler output.
func Captured(t *testing.T) []map[string]any {
	t.Helper()
	capturedMu.Lock()
	buf, ok := capturedBuf[t]
	capturedMu.Unlock()
	if !ok {
		t.Fatal("Captured called without a prior Capture call for this test")
	}
	var records []map[string]any
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for dec.More() {
		var r map[string]any
		if err := dec.Decode(&r); err != nil {
			break
		}
		records = append(records, r)
	}
	return records
}
