// SPDX-License-Identifier: Apache-2.0

package dataplane_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"protocolward.ai/ward/internal/dataplane"
	"protocolward.ai/ward/internal/obs"
)

// Serial: obs.Capture swaps the global slog default.
func TestServe_ShutdownRightAfterServe_ReturnsWithin1s(t *testing.T) {
	restore := obs.Capture(t) // keeps 200 `dns: listening` lines out of the test output
	defer restore()

	for i := range 200 {
		d := time.Duration(i%4) * time.Millisecond
		srv := newBindTestServer(t, "127.0.0.1:0")
		errCh := make(chan error, 1)
		go func() { errCh <- srv.Serve() }()
		if d > 0 {
			time.Sleep(d)
		}

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		shutErr := srv.Shutdown(ctx)
		cancel()
		if shutErr != nil && !errors.Is(shutErr, dataplane.ErrNotStarted) {
			t.Fatalf("iteration %d (delay %s): Shutdown = %v; want nil or an error wrapping dataplane.ErrNotStarted", i, d, shutErr)
		}

		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("iteration %d (delay %s): Serve = %v; want nil", i, d, err)
			}
		case <-time.After(time.Until(start.Add(time.Second))):
			t.Fatalf("iteration %d (delay %s): Serve did not return within 1s of Shutdown", i, d)
		}
	}
}

func TestServe_ShutdownBeforeServe_ReturnsNilWithoutServing(t *testing.T) {
	t.Parallel()
	srv := newBindTestServer(t, "127.0.0.1:0")
	_ = srv.Shutdown(context.Background()) // no listener yet: its ErrNotStarted is expected
	if err := serveWithin(t, srv, time.Second); err != nil {
		t.Fatalf("Serve after Shutdown = %v; want nil", err)
	}
	if addr := srv.Addr(); addr != "" {
		t.Errorf("Addr() = %q after Serve following Shutdown; want \"\" (nothing served)", addr)
	}
}

func TestShutdown_NeverServed_ReturnsErrNotStarted(t *testing.T) {
	t.Parallel()
	srv := newBindTestServer(t, "127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := srv.Shutdown(ctx)
	if !errors.Is(err, dataplane.ErrNotStarted) {
		t.Fatalf("Shutdown on a never-served server = %v; want an error wrapping dataplane.ErrNotStarted", err)
	}
	if strings.Contains(err.Error(), "server not started") {
		t.Errorf("Shutdown error %q carries miekg's message; want only ErrNotStarted's", err)
	}
}
