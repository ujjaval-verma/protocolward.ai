// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// pastDeadlineCtx has a deadline that has passed while its Err is still nil,
// as when the context's own timer has not fired yet.
type pastDeadlineCtx struct{ context.Context }

func (pastDeadlineCtx) Deadline() (time.Time, bool) { return time.Now().Add(-time.Second), true }

func TestDeadlineOutcome(t *testing.T) {
	t.Parallel()
	live := context.Background()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	past := pastDeadlineCtx{context.Background()}

	ioTimeout := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"live ctx, I/O deadline", live, ioTimeout, true},
		{"deadline passed, Err nil", past, io.EOF, true},
		{"cancelled ctx, EOF", cancelled, io.EOF, true},
		{"live ctx, EOF", live, io.EOF, false},
		{"live ctx, ECONNRESET", live, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, false},
		{"live ctx, kernel ETIMEDOUT", live, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ETIMEDOUT}, false},
		// A dial or handshake that timed out only on DialTimeout, with ctx
		// live, is retried as on main.
		{"live ctx, dial timeout", live, &DialError{Upstream: "x", Err: ioTimeout}, false},
		{"live ctx, handshake timeout", live, &TLSError{Upstream: "x", Err: context.DeadlineExceeded}, false},
	} {
		if got := isDeadlineOutcome(tc.ctx, tc.err); got != tc.want {
			t.Errorf("%s: isDeadlineOutcome = %v, want %v", tc.name, got, tc.want)
		}
	}

	if err := deadlineError(live); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("deadlineError(live ctx) = %v, want context.DeadlineExceeded", err)
	}
	if err := deadlineError(cancelled); !errors.Is(err, context.Canceled) {
		t.Errorf("deadlineError(cancelled ctx) = %v, want context.Canceled", err)
	}
}
