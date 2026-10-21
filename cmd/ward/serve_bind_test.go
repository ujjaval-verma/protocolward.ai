// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"protocolward.ai/ward/internal/dataplane"
)

// writeBindTestConfig writes a minimal ward.yaml that listens on listen.
// The upstream is never dialled: ward exits before any query.
func writeBindTestConfig(t *testing.T, listen string) string {
	t.Helper()
	body := fmt.Sprintf(`
upstreams:
  - address: "127.0.0.1:9999"
    server_name: "unused.test"
listen: %q
timeouts:
  shutdown: "200ms"
`, listen)
	p := filepath.Join(t.TempDir(), "ward.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// takeTCPPortWithFreeUDP holds a TCP listener on an ephemeral loopback port
// whose UDP twin is free right now. Same helper as in internal/dataplane's
// tests (separate package, so duplicated).
func takeTCPPortWithFreeUDP(t *testing.T) string {
	t.Helper()
	for range 20 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("pre-bind tcp: %v", err)
		}
		addr := ln.Addr().String()
		if pc, err := net.ListenPacket("udp", addr); err == nil {
			_ = pc.Close()
			t.Cleanup(func() { _ = ln.Close() })
			return addr
		}
		_ = ln.Close()
	}
	t.Fatal("no loopback port with a free UDP twin in 20 tries")
	return ""
}

// assertBindFailureExit runs the real binary against a taken DNS port and
// checks the issue #14 acceptance criteria: non-zero exit within 2 s and the
// bind remediation on stderr. Not parallel: the 2 s budget should not
// compete with the package's other subprocess tests for CPU.
func assertBindFailureExit(t *testing.T, addr string) {
	t.Helper()
	// Build and exec the binary once outside the timed window: the first exec
	// of a freshly built binary can be slow (macOS code-signing assessment),
	// and that is not ward's startup time.
	bin, err := buildWardBin()
	if err != nil {
		t.Fatalf("build ward: %v", err)
	}
	if out, err := exec.Command(bin, "version").CombinedOutput(); err != nil {
		t.Fatalf("warm-up ward version: %v\n%s", err, out)
	}
	cfg := writeBindTestConfig(t, addr)
	start := time.Now()
	code, stderr := runServeExpectingExit(t, cfg)
	elapsed := time.Since(start)
	if code == 0 {
		t.Errorf("exit code = 0; want non-zero. stderr:\n%s", stderr)
	}
	if elapsed > 2*time.Second {
		t.Errorf("ward serve took %s to exit; want <= 2s", elapsed)
	}
	want := "port already in use at " + addr
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr missing %q:\n%s", want, stderr)
	}
}

func TestServe_UDPPortTaken_ExitsNonZeroWithRemediation(t *testing.T) {
	held, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-bind udp: %v", err)
	}
	defer held.Close()
	assertBindFailureExit(t, held.LocalAddr().String())
}

func TestServe_TCPPortTaken_ExitsNonZeroWithRemediation(t *testing.T) {
	assertBindFailureExit(t, takeTCPPortWithFreeUDP(t))
}

// In-process: serveRun returns the bind error and does not leave the
// dashboard listener bound behind it.
func TestServeRun_DNSPortTaken_ReturnsBindErrorAndClosesDashboard(t *testing.T) {
	held, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-bind udp: %v", err)
	}
	defer held.Close()
	addr := held.LocalAddr().String()
	dashAddr := freeTCPAddr(t)

	done := make(chan error, 1)
	go func() {
		done <- serveRun(context.Background(), serveOpts{configPath: writeBindTestConfig(t, addr), dashListenAddr: dashAddr})
	}()
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveRun did not return within 2s with the DNS port taken")
	}
	var se *serveError
	if !errors.As(err, &se) || se.Code != 1 {
		t.Fatalf("serveRun = %v; want *serveError with Code 1", err)
	}
	if want := "port already in use at " + addr; !strings.Contains(se.Remediation, want) {
		t.Errorf("Remediation = %q; want it to contain %q", se.Remediation, want)
	}
	ln, err := rebindTCP(dashAddr)
	if err != nil {
		t.Fatalf("dashboard %s still bound after serveRun returned: %v", dashAddr, err)
	}
	_ = ln.Close()
}

func TestBindErrRemediation_ListenerStoppedAfterStart(t *testing.T) {
	stopped := fmt.Errorf("dataplane: udp listener on 127.0.0.1:5353 %w: %w",
		dataplane.ErrListenerStopped, net.ErrClosed)
	got := bindErrRemediation(stopped, "127.0.0.1:5353")
	want := "the DNS listener stopped unexpectedly; check the log above and restart ward"
	if got != want {
		t.Errorf("remediation = %q; want %q", got, want)
	}
	if strings.Contains(got, "ward.yaml") {
		t.Errorf("remediation %q must not carry the bind hint", got)
	}
}

// rebindTCP re-binds addr to prove a port was released. Another test may grab
// a just-freed ephemeral port, so it retries once after a short sleep.
func rebindTCP(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		time.Sleep(50 * time.Millisecond)
		ln, err = net.Listen("tcp", addr)
	}
	return ln, err
}
