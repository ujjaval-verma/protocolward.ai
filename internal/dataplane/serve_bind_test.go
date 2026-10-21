// SPDX-License-Identifier: Apache-2.0

package dataplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/dataplane"
)

// newBindTestServer returns an unstarted Server on listenAddr.
func newBindTestServer(t *testing.T, listenAddr string) *dataplane.Server {
	t.Helper()
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      listenAddr,
		Resolvers:       []dataplane.Resolver{&fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}},
		QueryTimeout:    2 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func TestServe_ShutdownAfterReady_ReturnsNil(t *testing.T) {
	srv := newBindTestServer(t, "127.0.0.1:0")
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve() }()
	if _, err := waitForAddr(srv, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve after Shutdown = %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return within 2s of Shutdown")
	}
}
