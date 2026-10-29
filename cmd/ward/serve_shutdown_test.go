// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
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
}

func newFakeSignals() *fakeSignals {
	return &fakeSignals{ch: make(chan os.Signal, 1), stopped: make(chan struct{})}
}

func (f *fakeSignals) notify() (<-chan os.Signal, func()) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
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
