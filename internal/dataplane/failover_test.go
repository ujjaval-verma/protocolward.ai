// SPDX-License-Identifier: Apache-2.0

package dataplane_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// hangingResolver returns a fake that blocks until ctx is done. The channel
// is closed at cleanup so nothing can outlive the test.
func hangingResolver(t *testing.T, addr string) *fakeResolver {
	t.Helper()
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	return &fakeResolver{addr: addr, rcode: dns.RcodeSuccess, hangCh: hang}
}

func TestFakeResolver_HangHonoursContext(t *testing.T) {
	r := hangingResolver(t, "10.0.0.1:853")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := r.Query(ctx, new(dns.Msg))
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Query error = %v; want context.DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hanging fake ignored ctx: Query still blocked 2s after a 20ms deadline")
	}
}

func TestFakeResolver_DoneContextFailsAtOnce(t *testing.T) {
	r := &fakeResolver{addr: "10.0.0.2:853", rcode: dns.RcodeSuccess}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Query(ctx, new(dns.Msg)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Query on a done ctx: error = %v; want context.Canceled", err)
	}
}
