// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// bindCallLog records, in order, every fake listen call and every Close of
// the sockets those calls returned.
type bindCallLog struct {
	mu     sync.Mutex
	events []string
	addrs  []string
}

func (l *bindCallLog) add(ev, addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, ev)
	l.addrs = append(l.addrs, addr)
}

func (l *bindCallLog) snapshot() (events, addrs []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...), append([]string(nil), l.addrs...)
}

// recordingPacketConn records Close, then closes the real socket it wraps.
type recordingPacketConn struct {
	net.PacketConn
	log *bindCallLog
}

func (c *recordingPacketConn) Close() error {
	c.log.add("udp-close", "")
	return c.PacketConn.Close()
}

// recordingListener records Close, then closes the real listener it wraps.
type recordingListener struct {
	net.Listener
	log *bindCallLog
}

func (l *recordingListener) Close() error {
	l.log.add("tcp-close", "")
	return l.Listener.Close()
}

// fakeUDPOK returns a listenUDP that records the call and hands back a real
// socket on 127.0.0.1:0 (the requested address is never bound).
func fakeUDPOK(t *testing.T, log *bindCallLog) func(network, address string) (net.PacketConn, error) {
	t.Helper()
	return func(network, address string) (net.PacketConn, error) {
		log.add("udp-listen:"+network, address)
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Errorf("fake udp socket: %v", err)
			return nil, err
		}
		return &recordingPacketConn{PacketConn: pc, log: log}, nil
	}
}

func TestProbeBind_HappyPath(t *testing.T) {
	var log bindCallLog
	listenTCP := func(network, address string) (net.Listener, error) {
		log.add("tcp-listen:"+network, address)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Errorf("fake tcp listener: %v", err)
			return nil, err
		}
		return &recordingListener{Listener: l, log: &log}, nil
	}

	if err := probeBindWith(placeholderListen, fakeUDPOK(t, &log), listenTCP); err != nil {
		t.Fatalf("probeBindWith(%q): %v", placeholderListen, err)
	}
	events, addrs := log.snapshot()
	wantEvents := []string{"udp-listen:udp", "udp-close", "tcp-listen:tcp", "tcp-close"}
	if !slices.Equal(events, wantEvents) {
		t.Fatalf("events = %v; want %v", events, wantEvents)
	}
	if addrs[0] != placeholderListen || addrs[2] != placeholderListen {
		t.Errorf("listen addresses = %q, %q; want %q for both", addrs[0], addrs[2], placeholderListen)
	}
}

func TestProbeBind_TCPInUse_Fails(t *testing.T) {
	var log bindCallLog
	listenTCP := func(network, address string) (net.Listener, error) {
		log.add("tcp-listen:"+network, address)
		return nil, &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	}

	err := probeBindWith(placeholderListen, fakeUDPOK(t, &log), listenTCP)
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("err = %v; want it to wrap EADDRINUSE", err)
	}
	if !strings.Contains(err.Error(), "tcp bind") || !strings.Contains(err.Error(), placeholderListen) {
		t.Errorf("err = %q; want it to name %q and %q", err, "tcp bind", placeholderListen)
	}
	events, _ := log.snapshot()
	wantEvents := []string{"udp-listen:udp", "udp-close", "tcp-listen:tcp"}
	if !slices.Equal(events, wantEvents) {
		t.Errorf("events = %v; want %v (UDP closed before TCP tried)", events, wantEvents)
	}
}

func TestProbeBind_UDPInUse_NeverTriesTCP(t *testing.T) {
	listenUDP := func(string, string) (net.PacketConn, error) {
		return nil, &net.OpError{Op: "listen", Net: "udp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	}
	listenTCP := func(string, string) (net.Listener, error) {
		t.Error("listenTCP called after the UDP bind failed")
		return nil, errors.New("unexpected")
	}

	err := probeBindWith(placeholderListen, listenUDP, listenTCP)
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("err = %v; want it to wrap EADDRINUSE", err)
	}
	if !strings.Contains(err.Error(), "udp bind") {
		t.Errorf("err = %q; want it to contain %q", err, "udp bind")
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

// recordingBindProbe is a doctorOpts.bindProbe fake that records its calls.
type recordingBindProbe struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (r *recordingBindProbe) probe(listenAddr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, listenAddr)
	return r.err
}

func (r *recordingBindProbe) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// holdUpstream listens on 127.0.0.1:0 for the whole test and accepts and
// closes connections, so the doctor's upstream probe succeeds.
func holdUpstream(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().String()
}

func TestDoctorRun_AllProbesGreen(t *testing.T) {
	cfgPath := writeWardYAMLForDoctor(t, placeholderListen, holdUpstream(t))

	var bp recordingBindProbe
	var buf bytes.Buffer
	if err := doctorRun(&buf, doctorOpts{configPath: cfgPath, bindProbe: bp.probe}); err != nil {
		t.Fatalf("doctorRun: %v\n%s", err, buf.String())
	}
	if got := bp.recorded(); !slices.Equal(got, []string{placeholderListen}) {
		t.Errorf("bindProbe calls = %v; want exactly [%s]", got, placeholderListen)
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
	cfgPath := writeWardYAMLForDoctor(t, placeholderListen, "127.0.0.1:1")

	var bp recordingBindProbe
	var buf bytes.Buffer
	err := doctorRun(&buf, doctorOpts{configPath: cfgPath, bindProbe: bp.probe})
	if err == nil {
		t.Fatalf("expected non-nil error (probe FAIL), got nil; output:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "[FAIL]") {
		t.Errorf("output missing '[FAIL]'; got:\n%s", buf.String())
	}
	if got := bp.recorded(); !slices.Equal(got, []string{placeholderListen}) {
		t.Errorf("bindProbe calls = %v; want exactly [%s]", got, placeholderListen)
	}
}

func TestDoctorRun_BindProbeFails_ReportsFail(t *testing.T) {
	cfgPath := writeWardYAMLForDoctor(t, placeholderListen, holdUpstream(t))

	bp := recordingBindProbe{err: &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}}
	var buf bytes.Buffer
	err := doctorRun(&buf, doctorOpts{configPath: cfgPath, bindProbe: bp.probe})
	var se *serveError
	if !errors.As(err, &se) {
		t.Fatalf("err = %T %v; want *serveError", err, err)
	}
	if se.Code != 1 {
		t.Errorf("Code = %d want 1", se.Code)
	}
	out := buf.String()
	for _, want := range []string{
		"[FAIL]",
		" bind 127.0.0.1:5354",
		"remediation: port already in use at 127.0.0.1:5354; stop the process using that port or change listen in ward.yaml",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

// A nil bindProbe selects the real probeBind. Holding a UDP socket makes the
// real probe fail, so this fails if the nil default is ever replaced by a
// no-op.
func TestDoctorRun_DefaultBindProbe_HeldUDP_ReportsFail(t *testing.T) {
	held, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold udp: %v", err)
	}
	defer held.Close()
	addr := held.LocalAddr().String()
	cfgPath := writeWardYAMLForDoctor(t, addr, holdUpstream(t))

	var buf bytes.Buffer
	if err := doctorRun(&buf, doctorOpts{configPath: cfgPath}); err == nil {
		t.Fatalf("expected non-nil error with %s held; output:\n%s", addr, buf.String())
	}
	out := buf.String()
	for _, want := range []string{"[FAIL]", " bind " + addr} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

func TestDoctorRun_UnknownKey_ExitsCode2(t *testing.T) {
	p := writeExampleWithBogusKey(t)
	var buf bytes.Buffer
	failIfCalled := func(listenAddr string) error {
		t.Errorf("bindProbe called with %q; a config error must stop before probing", listenAddr)
		return nil
	}
	err := doctorRun(&buf, doctorOpts{configPath: p, bindProbe: failIfCalled})
	var se *serveError
	if !errors.As(err, &se) {
		t.Fatalf("err = %T %v; want *serveError", err, err)
	}
	if se.Code != 2 {
		t.Errorf("Code = %d want 2", se.Code)
	}
	if !strings.Contains(se.Message, `unknown key "bogus_typo_field"`) {
		t.Errorf("Message = %q", se.Message)
	}
	if se.Remediation != unknownKeyRemediation {
		t.Errorf("Remediation = %q", se.Remediation)
	}
	if strings.Contains(buf.String(), "[FAIL]") || strings.Contains(buf.String(), "[OK]") {
		t.Errorf("doctor probed upstreams: %q", buf.String())
	}
}
