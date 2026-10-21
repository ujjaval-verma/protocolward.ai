// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
