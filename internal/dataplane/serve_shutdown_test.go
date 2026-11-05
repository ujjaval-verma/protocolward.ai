// SPDX-License-Identifier: Apache-2.0

package dataplane_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"protocolward.ai/ward/internal/dataplane"
)

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
