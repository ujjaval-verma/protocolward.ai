// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/config"
	"protocolward.ai/ward/internal/dataplane"
	"protocolward.ai/ward/internal/upstream"
)

// blackHoleUpstream listens on a kernel-assigned loopback TCP port, accepts
// every connection and holds it without writing, so a DoT dial to it hangs in
// the handshake. accepted is closed on the first accepted connection; the
// loop keeps accepting (the upstream retries once on a fresh dial) until the
// listener closes. Cleanup closes the listener and the held connections and
// waits for the accept goroutine.
func blackHoleUpstream(t *testing.T) (addr string, accepted <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	acc := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	var conns []net.Conn
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			once.Do(func() { close(acc) })
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-loopDone
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String(), acc
}

// A second SIGINT while ward drains an in-flight query exits at once with
// code 130 and never reaches `ward serve: stopped`.
func TestServe_SecondSignalDuringDrain_Exits130(t *testing.T) {
	t.Parallel()
	upAddr, accepted := blackHoleUpstream(t)
	w := startWard(t, "upstreams:\n  - address: \""+upAddr+"\"\n    server_name: \"blackhole.test\"\n"+
		"timeouts:\n  dial: \"20s\"\n  query: \"20s\"\n  shutdown: \"20s\"\n")

	conn, err := net.Dial("udp", w.dnsAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	packed, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(packed); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatalf("upstream never saw a connection; the query is not in flight\nlog:\n%s", w.out.String())
	}

	if err := w.proc.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if _, err := w.waitFor("ward serve: shutdown signal received; draining in-flight queries"); err != nil {
		t.Fatalf("%v", err)
	}
	select {
	case <-w.exited:
		t.Fatalf("ward exited (code %d) before the second signal\nlog:\n%s", w.exitCode, w.out.String())
	default:
	}
	if err := w.proc.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.exited:
	case <-time.After(5 * time.Second):
		t.Fatalf("ward did not exit within 5s of the second signal\nlog:\n%s", w.out.String())
	}
	if w.exitCode != 130 {
		t.Errorf("exit code = %d, want 130\nlog:\n%s", w.exitCode, w.out.String())
	}
	if m := w.scan("ward serve: stopped"); m != nil {
		t.Errorf("ward logged %q on the second-signal path; want an immediate exit\nlog:\n%s", "ward serve: stopped", w.out.String())
	}
}

// hatchRecorder records hatch side effects in order under a mutex. Its exit
// and Close methods stand in for os.Exit and the dashboard's Close.
type hatchRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *hatchRecorder) add(e string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *hatchRecorder) exit(code int) { r.add("exit " + strconv.Itoa(code)) }

func (r *hatchRecorder) Close() error {
	r.add("close")
	return nil
}

func (r *hatchRecorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

// fakeSignals is a signalNotifier whose 1-buffered channel the test owns.
// stopped is closed (once) when the hatch unsubscribes.
type fakeSignals struct {
	ch       chan os.Signal
	stopped  chan struct{}
	stopOnce sync.Once
	mu       sync.Mutex
	calls    int
	onNotify func() // optional; runs inside notify
}

func newFakeSignals() *fakeSignals {
	return &fakeSignals{ch: make(chan os.Signal, 1), stopped: make(chan struct{})}
}

func (f *fakeSignals) notify() (<-chan os.Signal, func()) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.onNotify != nil {
		f.onNotify()
	}
	return f.ch, func() { f.stopOnce.Do(func() { close(f.stopped) }) }
}

func (f *fakeSignals) notifyCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// trySend delivers a signal without blocking: after disarm or expiry nothing
// reads the channel, so a blocking send could hang the test.
func (f *fakeSignals) trySend() {
	select {
	case f.ch <- os.Interrupt:
	default:
	}
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: not closed within 5s", what)
	}
}

// hatchBudget is long enough that the timer branch is never ready alongside
// done or a signal; only the expiry subtest uses a short budget.
const hatchBudget = time.Minute

var closeThenExit = []string{"close", "exit 130"}

func TestExitHatch(t *testing.T) {
	t.Run("signal", func(t *testing.T) {
		sig, rec := newFakeSignals(), &hatchRecorder{}
		h := newExitHatch(sig.notify, rec.exit)
		h.arm(hatchBudget, rec)
		sig.ch <- os.Interrupt
		waitClosed(t, sig.stopped, "stopped after a signal")
		h.disarm()
		if got := rec.got(); !reflect.DeepEqual(got, closeThenExit) {
			t.Fatalf("events = %q, want %q", got, closeThenExit)
		}
	})
	t.Run("disarm without signal", func(t *testing.T) {
		sig, rec := newFakeSignals(), &hatchRecorder{}
		h := newExitHatch(sig.notify, rec.exit)
		h.arm(hatchBudget, rec)
		h.disarm()
		if !isClosed(sig.stopped) {
			t.Fatal("still subscribed when disarm returned")
		}
		sig.trySend()
		if got := rec.got(); len(got) != 0 {
			t.Fatalf("events = %q, want none", got)
		}
	})
	t.Run("expiry", func(t *testing.T) {
		sig, rec := newFakeSignals(), &hatchRecorder{}
		h := newExitHatch(sig.notify, rec.exit)
		h.arm(time.Millisecond, rec)
		waitClosed(t, sig.stopped, "stopped after the budget")
		sig.trySend()
		h.disarm()
		if got := rec.got(); len(got) != 0 {
			t.Fatalf("events = %q, want none after expiry", got)
		}
	})
	t.Run("pending", func(t *testing.T) {
		// The signal is buffered before arm, and disarm follows arm at once,
		// so the hatch goroutine's first select finds both done and the signal
		// ready. Without the re-check in the done case it drops the signal
		// about half the time.
		for i := range 50 {
			sig, rec := newFakeSignals(), &hatchRecorder{}
			sig.ch <- os.Interrupt
			h := newExitHatch(sig.notify, rec.exit)
			h.arm(hatchBudget, rec)
			h.disarm()
			if got := rec.got(); !reflect.DeepEqual(got, closeThenExit) {
				t.Fatalf("iteration %d: events = %q, want %q (a pending signal must fire at disarm)", i, got, closeThenExit)
			}
			if !isClosed(sig.stopped) {
				t.Fatalf("iteration %d: still subscribed when disarm returned", i)
			}
		}
	})
	t.Run("armed twice", func(t *testing.T) {
		sig, rec := newFakeSignals(), &hatchRecorder{}
		h := newExitHatch(sig.notify, rec.exit)
		h.arm(hatchBudget, rec)
		h.arm(hatchBudget, rec)
		if n := sig.notifyCalls(); n != 1 {
			t.Fatalf("notifier called %d times by two arms, want 1", n)
		}
		h.disarm()
		if !isClosed(sig.stopped) {
			t.Fatal("still subscribed after one disarm of a twice-armed hatch")
		}
		if got := rec.got(); len(got) != 0 {
			t.Fatalf("events = %q, want none", got)
		}
	})
	t.Run("unarmed and twice", func(t *testing.T) {
		sig, rec := newFakeSignals(), &hatchRecorder{}
		h := newExitHatch(sig.notify, rec.exit)
		h.disarm()
		if n := sig.notifyCalls(); n != 0 {
			t.Fatalf("notifier called %d times by disarm on an unarmed hatch, want 0", n)
		}
		h.arm(hatchBudget, rec)
		h.disarm()
		h.disarm()
		if got := rec.got(); len(got) != 0 {
			t.Fatalf("events = %q, want none", got)
		}
	})
}

// runServeWithHatch starts serveRun in-process with fake hatch seams, waits
// until it answers DNS (SERVFAIL: the upstream is dead), cancels it and
// returns its result.
func runServeWithHatch(t *testing.T, sig *fakeSignals, rec *hatchRecorder) error {
	t.Helper()
	captureSlog(t)
	cfgPath := serveMinimalCfg(t, "")
	dnsAddr := serveCfgListen(t, cfgPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveRun(ctx, serveOpts{
			configPath:     cfgPath,
			dashListenAddr: freeTCPAddr(t),
			notifySignals:  sig.notify,
			exit:           rec.exit,
		})
	}()
	c := &dns.Client{Timeout: 500 * time.Millisecond}
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, _, err := c.Exchange(q, dnsAddr); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("serveRun returned %v before answering DNS", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no DNS answer from %s within 5s", dnsAddr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("serveRun did not return within 5s of cancel")
		return nil
	}
}

func TestServeRun_SecondSignal_Exits130(t *testing.T) {
	sig, rec := newFakeSignals(), &hatchRecorder{}
	sig.ch <- os.Interrupt
	if err := runServeWithHatch(t, sig, rec); err != nil {
		t.Fatalf("serveRun = %v, want nil", err)
	}
	if got, want := rec.got(), []string{"exit 130"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("exit calls = %q, want %q", got, want)
	}
	if !isClosed(sig.stopped) {
		t.Fatal("hatch still subscribed after serveRun returned")
	}
	sig.trySend()
	if got := rec.got(); len(got) != 1 {
		t.Fatalf("exit calls after return = %q, want exactly one", got)
	}
}

func TestServeRun_Return_DisarmsHatch(t *testing.T) {
	sig, rec := newFakeSignals(), &hatchRecorder{}
	if err := runServeWithHatch(t, sig, rec); err != nil {
		t.Fatalf("serveRun = %v, want nil", err)
	}
	if !isClosed(sig.stopped) {
		t.Fatal("hatch still subscribed after serveRun returned")
	}
	sig.trySend()
	if got := rec.got(); len(got) != 0 {
		t.Fatalf("exit calls = %q, want none", got)
	}
}

// fakeDash is a recording dashServer. Close appends "close" to rec (shared
// with a hatch recorder when a test needs one order across both).
type fakeDash struct {
	rec         *hatchRecorder
	shutdownErr error

	mu        sync.Mutex
	shutdowns int
	deadline  time.Duration // time left on the last Shutdown context
	hasDL     bool
}

func newFakeDash(rec *hatchRecorder) *fakeDash { return &fakeDash{rec: rec} }

func (d *fakeDash) Close() error {
	d.rec.add("close")
	return nil
}

func (d *fakeDash) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.shutdowns++
	dl, ok := ctx.Deadline()
	d.deadline, d.hasDL = time.Until(dl), ok
	return d.shutdownErr
}

func (d *fakeDash) shutdownCalls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.shutdowns
}

// newTestDataplane builds a real dataplane server on addr with one upstream
// that refuses connections. It is not served.
func newTestDataplane(t *testing.T, addr string) *dataplane.Server {
	t.Helper()
	up, err := upstream.New(upstream.Config{Address: "127.0.0.1:1", ServerName: "unreachable.test", DialTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := dataplane.NewServer(dataplane.Config{ListenAddr: addr, Resolvers: []dataplane.Resolver{up}})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// logLines decodes the captured slog JSON lines.
func logLines(t *testing.T, buf *safeBuffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	dec := json.NewDecoder(strings.NewReader(buf.String()))
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode log: %v\nlog:\n%s", err, buf.String())
		}
		out = append(out, m)
	}
	return out
}

// logIndex returns the index of the first captured line whose msg is msg,
// or -1.
func logIndex(lines []map[string]any, msg string) int {
	for i, m := range lines {
		if m["msg"] == msg {
			return i
		}
	}
	return -1
}

const (
	msgShutdownReceived = "ward serve: shutdown signal received; draining in-flight queries"
	msgStopped          = "ward serve: stopped"
	msgNotStarted       = "ward serve: shutdown called before server fully started; nothing to drain"
)

func TestShutdownServe(t *testing.T) {
	const budget = 2 * time.Second
	run := func(t *testing.T, dash *fakeDash, serveErr chan error) time.Duration {
		t.Helper()
		srv := newTestDataplane(t, "127.0.0.1:0")
		done := make(chan struct{})
		start := time.Now()
		go func() {
			defer close(done)
			shutdownServe(srv, dash, serveErr, budget)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("shutdownServe did not return within 3s")
		}
		return time.Since(start)
	}
	t.Run("serve already returned", func(t *testing.T) {
		buf := captureSlog(t)
		dash := newFakeDash(&hatchRecorder{})
		serveErr := make(chan error, 1)
		serveErr <- nil
		if took := run(t, dash, serveErr); took > 400*time.Millisecond {
			t.Errorf("shutdownServe took %s with serveErr ready, want <= 400ms", took)
		}
		if n := dash.shutdownCalls(); n != 1 {
			t.Fatalf("dashboard Shutdown calls = %d, want 1", n)
		}
		if !dash.hasDL || dash.deadline > time.Second {
			t.Errorf("dashboard Shutdown deadline = %s (set %v), want <= 1s away", dash.deadline, dash.hasDL)
		}
		lines := logLines(t, buf)
		ns, st := logIndex(lines, msgNotStarted), logIndex(lines, msgStopped)
		if ns < 0 || st < 0 || ns > st {
			t.Errorf("want %q then %q; got indices %d, %d\nlog:\n%s", msgNotStarted, msgStopped, ns, st, buf.String())
		}
		if ns >= 0 && lines[ns]["level"] != "DEBUG" {
			t.Errorf("%q level = %v, want DEBUG", msgNotStarted, lines[ns]["level"])
		}
		if i := logIndex(lines, "ward serve: shutdown error"); i >= 0 {
			t.Errorf("unexpected shutdown error line: %v", lines[i])
		}
	})
	t.Run("dashboard shutdown error", func(t *testing.T) {
		buf := captureSlog(t)
		dash := newFakeDash(&hatchRecorder{})
		dash.shutdownErr = errors.New("dash stuck")
		serveErr := make(chan error, 1)
		serveErr <- nil
		run(t, dash, serveErr)
		lines := logLines(t, buf)
		i := logIndex(lines, "dashboard: shutdown error")
		if i < 0 {
			t.Fatalf("no dashboard: shutdown error line\nlog:\n%s", buf.String())
		}
		if lines[i]["level"] != "WARN" || lines[i]["error"] != "dash stuck" {
			t.Errorf("dashboard: shutdown error line = %v, want WARN with error %q", lines[i], "dash stuck")
		}
	})
	t.Run("serve still running", func(t *testing.T) {
		buf := captureSlog(t)
		dash := newFakeDash(&hatchRecorder{})
		if took := run(t, dash, make(chan error, 1)); took < 500*time.Millisecond {
			t.Errorf("shutdownServe took %s with serveErr empty, want the 500ms drain", took)
		}
		if logIndex(logLines(t, buf), msgStopped) < 0 {
			t.Errorf("no %q line\nlog:\n%s", msgStopped, buf.String())
		}
	})
}

func TestServeUntilStopped(t *testing.T) {
	const budget = 2 * time.Second
	// run calls serveUntilStopped in a goroutine and returns its result. It
	// disarms the hatch only after the result arrived, so arm and disarm are
	// ordered by the channel handoff; on a timeout it fails without disarming.
	run := func(t *testing.T, ctx context.Context, srv *dataplane.Server, dash dashServer, hatch *exitHatch, cfg config.Config, fromFlag bool, started func()) error {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- serveUntilStopped(ctx, srv, dash, hatch, cfg, fromFlag) }()
		if started != nil {
			started()
		}
		select {
		case err := <-done:
			hatch.disarm()
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("serveUntilStopped did not return within 5s")
			return nil
		}
	}

	t.Run("listener exit", func(t *testing.T) {
		for _, tc := range []struct {
			fromFlag bool
			wantRem  string
		}{
			{false, "; stop the process using that port or change listen in ward.yaml"},
			{true, "; stop the process using that port or change --listen-addr"},
		} {
			captureSlog(t)
			held, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := held.LocalAddr().String()
			srv := newTestDataplane(t, addr)
			sig, rec := newFakeSignals(), &hatchRecorder{}
			dash := newFakeDash(rec)
			cfg := config.Config{Listen: addr, Timeouts: config.Timeouts{Shutdown: budget}}
			err = run(t, context.Background(), srv, dash, newExitHatch(sig.notify, rec.exit), cfg, tc.fromFlag, nil)
			_ = held.Close()
			se := asServeError(t, err, 1)
			if !strings.HasPrefix(se.Message, "listener error:") {
				t.Errorf("fromFlag=%v: Message = %q, want prefix %q", tc.fromFlag, se.Message, "listener error:")
			}
			if want := "port already in use at " + addr + tc.wantRem; se.Remediation != want {
				t.Errorf("fromFlag=%v: Remediation = %q, want %q", tc.fromFlag, se.Remediation, want)
			}
			if got := rec.got(); !reflect.DeepEqual(got, []string{"close"}) {
				t.Errorf("fromFlag=%v: events = %q, want the dashboard closed once", tc.fromFlag, got)
			}
			if n := sig.notifyCalls(); n != 0 {
				t.Errorf("fromFlag=%v: hatch armed %d times on the listener-exit path, want 0", tc.fromFlag, n)
			}
		}
	})

	// graceful runs the first-signal path; the returned recorder holds the
	// dashboard Close and exit calls in one order.
	graceful := func(t *testing.T, preload bool) (*hatchRecorder, *fakeDash) {
		t.Helper()
		buf := captureSlog(t)
		srv := newTestDataplane(t, "127.0.0.1:0")
		sig, rec := newFakeSignals(), &hatchRecorder{}
		if preload {
			sig.ch <- os.Interrupt
		}
		logAtArm := make(chan bool, 1)
		sig.onNotify = func() { logAtArm <- strings.Contains(buf.String(), msgShutdownReceived) }
		dash := newFakeDash(rec)
		cfg := config.Config{Listen: "127.0.0.1:0", Timeouts: config.Timeouts{Shutdown: budget}}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		err := run(t, ctx, srv, dash, newExitHatch(sig.notify, rec.exit), cfg, false, func() {
			deadline := time.Now().Add(5 * time.Second)
			for srv.Addr() == "" {
				if time.Now().After(deadline) {
					t.Fatal("dataplane not serving within 5s")
				}
				time.Sleep(5 * time.Millisecond)
			}
			cancel()
		})
		if err != nil {
			t.Fatalf("serveUntilStopped = %v, want nil", err)
		}
		if n := sig.notifyCalls(); n != 1 {
			t.Fatalf("hatch armed %d times, want 1", n)
		}
		if <-logAtArm {
			t.Errorf("%q was logged before the hatch was armed", msgShutdownReceived)
		}
		lines := logLines(t, buf)
		rcv, st := logIndex(lines, msgShutdownReceived), logIndex(lines, msgStopped)
		if rcv < 0 || st < 0 || rcv > st {
			t.Fatalf("want %q then %q; got indices %d, %d\nlog:\n%s", msgShutdownReceived, msgStopped, rcv, st, buf.String())
		}
		if _, ok := lines[rcv]["shutdown_budget"]; !ok {
			t.Errorf("%q has no shutdown_budget field: %v", msgShutdownReceived, lines[rcv])
		}
		if n := dash.shutdownCalls(); n != 1 {
			t.Errorf("dashboard Shutdown calls = %d, want 1", n)
		}
		return rec, dash
	}

	t.Run("graceful", func(t *testing.T) {
		rec, _ := graceful(t, false)
		if got := rec.got(); len(got) != 0 {
			t.Errorf("events = %q, want none on the graceful path", got)
		}
	})
	t.Run("graceful with a pending second signal", func(t *testing.T) {
		// serveUntilStopped never calls dash.Close on the graceful path, so
		// "close" can only come from the hatch.
		rec, _ := graceful(t, true)
		if got := rec.got(); !reflect.DeepEqual(got, closeThenExit) {
			t.Errorf("events = %q, want %q", got, closeThenExit)
		}
	})
}

// A second signal that arrives while serveRun is reaping the model child
// still exits 130: the hatch is disarmed only after the reap. The child holds
// the reap open until the close grace kills it, so the signal lands inside it.
func TestServeRun_SignalDuringReap_Exits130(t *testing.T) {
	captureSlog(t) // registered first, so it is restored last
	logs := captureStdout(t)
	sig, rec := newFakeSignals(), &hatchRecorder{}
	// The child answers one request, records that it did, then ignores stdin
	// EOF's invitation to exit by sleeping until the close grace kills it. The
	// adapter starts the child on the first classification, so there is
	// nothing to reap until a query has been sent.
	started := filepath.Join(t.TempDir(), "started")
	script := `read -r _; echo '{"verdict":"benign"}'; : > "$1"; cat >/dev/null; exec sleep 30`
	cfgPath := serveMinimalCfg(t, fmt.Sprintf("model:\n  command:\n    - /bin/sh\n    - -c\n    - %q\n    - sh\n    - %q\n", script, started))
	dnsAddr := serveCfgListen(t, cfgPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveRun(ctx, serveOpts{
			configPath:     cfgPath,
			dashListenAddr: freeTCPAddr(t),
			notifySignals:  sig.notify,
			exit:           rec.exit,
		})
	}()
	// Bounded on every path: the child is killed by the 2s close grace, and
	// the deferred wait below blocks until serveRun (and so the reap) is over.
	returned := false
	defer func() {
		cancel()
		if returned {
			return
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("serveRun did not return within 10s")
		}
	}()

	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s not seen within 5s\nlog:\n%s", what, logs.String())
			}
		}
	}
	waitFor("dns: listening", func() bool { return strings.Contains(logs.String(), "dns: listening") })
	c := &dns.Client{Timeout: 500 * time.Millisecond}
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	_, _, _ = c.Exchange(q, dnsAddr) // SERVFAIL (dead upstream); the classification still runs
	waitFor("the model child's reply", func() bool { _, err := os.Stat(started); return err == nil })
	cancel()
	waitFor("ward serve: stopped", func() bool { return strings.Contains(logs.String(), "ward serve: stopped") })
	if got := rec.got(); len(got) != 0 {
		t.Fatalf("events before the second signal = %q, want none", got)
	}
	sig.trySend()
	select {
	case err := <-done:
		returned = true
		if err != nil {
			t.Fatalf("serveRun = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveRun did not return within 10s")
	}
	// The injected exit returns, so serveRun runs on; disarm then waits for
	// the hatch goroutine, so by now the exit has been recorded.
	if got, want := rec.got(), []string{"exit 130"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("exit calls = %q, want %q (a second signal during the reap must exit 130)", got, want)
	}
	if !isClosed(sig.stopped) {
		t.Fatal("hatch still subscribed after serveRun returned")
	}
}

// captureStdout redirects os.Stdout into the returned buffer until cleanup.
// serveRun installs a logger that writes to os.Stdout, so this is how an
// in-process test reads its log lines. Only non-parallel tests may use it.
func captureStdout(t *testing.T) *safeBuffer {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	buf := &safeBuffer{}
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		_, _ = io.Copy(buf, r)
	}()
	prev := os.Stdout
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = prev
		_ = w.Close()
		<-copied
		_ = r.Close()
	})
	return buf
}
