// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProbeBind_HappyPath(t *testing.T) {
	// Use 127.0.0.1:0 to let the OS pick a free port. We cannot use
	// probeBind directly with :0 because it binds and releases twice (once
	// for UDP, once for TCP) and the OS will assign different ports.
	// Instead, reserve a free TCP port, release it, and reuse the number.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	// Small grace to let the OS release.
	time.Sleep(10 * time.Millisecond)

	if err := probeBind(addr); err != nil {
		t.Errorf("probeBind(%q): %v", addr, err)
	}
}

func TestProbeBind_AddressInUse_Fails(t *testing.T) {
	// Bind a UDP socket and keep it open, so probeBind hits "address in use".
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold port: %v", err)
	}
	defer l.Close()
	addr := l.LocalAddr().String()

	err = probeBind(addr)
	if err == nil {
		t.Errorf("probeBind(%q): expected error when port held, got nil", addr)
	}
}

func TestProbeUpstream_ReachableSucceeds(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	r := probeUpstream(l.Addr().String(), 1*time.Second)
	if !r.OK {
		t.Errorf("probeUpstream(%q): got OK=false detail=%q want OK=true", l.Addr().String(), r.Detail)
	}
}

func TestProbeUpstream_UnreachableFails(t *testing.T) {
	// 127.0.0.1:1 is reserved (tcpmux) and almost never bound — DialTimeout
	// will return connection-refused quickly.
	r := probeUpstream("127.0.0.1:1", 500*time.Millisecond)
	if r.OK {
		t.Errorf("probeUpstream(127.0.0.1:1): expected OK=false, got OK=true")
	}
	if r.Detail == "" {
		t.Errorf("probeUpstream failure: expected non-empty Detail")
	}
}

// writeWardYAMLForDoctor writes a minimum-valid ward.yaml pointing the upstream
// at the given address; returns the yaml path.
func writeWardYAMLForDoctor(t *testing.T, listen, upstreamAddr string) string {
	t.Helper()
	body := `listen: "` + listen + `"
log_level: "info"
upstreams:
  - address: "` + upstreamAddr + `"
    server_name: "doctor.test"
timeouts:
  dial: "1s"
  query: "1s"
  shutdown: "1s"
`
	p := filepath.Join(t.TempDir(), "ward.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestDoctorRun_AllProbesGreen(t *testing.T) {
	// Reserve a free port for ward listen + a separate TCP listener for upstream.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve listen: %v", err)
	}
	listenAddr := l.Addr().String()
	l.Close()
	time.Sleep(10 * time.Millisecond)

	upstreamL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstreamL.Close()
	go func() {
		for {
			c, err := upstreamL.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	cfgPath := writeWardYAMLForDoctor(t, listenAddr, upstreamL.Addr().String())

	var buf bytes.Buffer
	err = doctorRun(&buf, doctorOpts{configPath: cfgPath})
	if err != nil {
		t.Fatalf("doctorRun: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "bind") {
		t.Errorf("output missing 'bind'; got:\n%s", out)
	}
	if !strings.Contains(out, "upstream") {
		t.Errorf("output missing 'upstream'; got:\n%s", out)
	}
	if !strings.Contains(out, "[OK]") {
		t.Errorf("output missing '[OK]'; got:\n%s", out)
	}
}

func TestDoctorRun_UpstreamUnreachable_ExitsNonZero(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	listenAddr := l.Addr().String()
	l.Close()
	time.Sleep(10 * time.Millisecond)

	cfgPath := writeWardYAMLForDoctor(t, listenAddr, "127.0.0.1:1")

	var buf bytes.Buffer
	err = doctorRun(&buf, doctorOpts{configPath: cfgPath})
	if err == nil {
		t.Fatalf("expected non-nil error (probe FAIL), got nil; output:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "[FAIL]") {
		t.Errorf("output missing '[FAIL]'; got:\n%s", buf.String())
	}
}
